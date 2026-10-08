from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from pydantic import ValidationError
import httpx
import re
import secrets
import hashlib
import logging
import time
import threading

from backend.database.session import get_db, SessionLocal
from backend.models.models import User, PasswordResetToken
from backend.models.schemas import (
    UserCreate,
    UserOut,
    Token,
    LoginRequest,
    GoogleAuthRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from backend.utils.config import settings
from backend.utils.security import verify_password, get_password_hash, create_access_token
from backend.utils.email import send_password_reset_email

logger = logging.getLogger(__name__)

# In-memory rate limiter for password reset requests.
# NOTE: This in-memory state resets on server restart and does not span multiple
# worker processes or server instances. For distributed multi-instance deployments,
# a centralized store (e.g., Redis) should be used.
_reset_rate_limit_lock = threading.Lock()
_reset_rate_limit_records: dict[str, list[float]] = {}

def _check_and_record_rate_limit(key: str, limit: int, window_seconds: int = 3600) -> bool:
    """
    Checks if `key` has exceeded `limit` attempts within `window_seconds`.
    Always records the attempt regardless of whether the limit is exceeded.
    Returns True if allowed, False if exceeded.
    """
    now = time.time()
    cutoff = now - window_seconds
    with _reset_rate_limit_lock:
        existing = [ts for ts in _reset_rate_limit_records.get(key, []) if ts > cutoff]
        existing.append(now)
        _reset_rate_limit_records[key] = existing
        # If count strictly exceeds limit (the current attempt makes it > limit)
        if len(existing) > limit:
            return False
        return True

def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"

def _process_forgot_password(email: str) -> None:
    """
    Background worker for password reset request.
    Does the user lookup, token generation, and email dispatch asynchronously
    so response timing does not leak account existence.
    """
    db: Session = SessionLocal()
    try:
        norm_email = email.strip().lower()
        user = db.query(User).filter(User.email == norm_email).first()
        if not user or not user.is_active:
            return

        now = datetime.utcnow()
        # Invalidate any earlier unused tokens for this user
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None)
        ).update({"used_at": now})

        # Generate cryptographic random token and store its SHA-256 hash
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES)

        token_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            created_at=now,
            expires_at=expires_at,
            used_at=None,
        )
        db.add(token_record)
        db.commit()

        reset_link = f"{settings.FRONTEND_URL.rstrip('/')}/reset-password?token={raw_token}"
        send_password_reset_email(user.email, reset_link)
    except Exception as e:
        logger.error("Failed to process background forgot-password task: %s", e)
        db.rollback()
    finally:
        db.close()

router = APIRouter(prefix="/auth", tags=["Authentication"])

security_scheme = HTTPBearer(auto_error=True)

def get_current_user(db: Session = Depends(get_db), credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> User:
    """
    Dependency to validate JWT access token and return the current active User.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        import uuid
        try:
            user_id = uuid.UUID(user_id_str)
        except ValueError:
            raise credentials_exception
    except (JWTError, ValidationError):
        raise credentials_exception
        
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user


@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user account.
    """
    # Check if username exists
    existing_username = db.query(User).filter(User.username == user_in.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this username already exists in the system."
        )
        
    # Check if email exists
    existing_email = db.query(User).filter(User.email == user_in.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system."
        )
        
    db_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates a user via JSON request body and returns a JWT access token.
    """
    # Find user by username or email
    user = db.query(User).filter(
        (User.username == login_data.username) | (User.email == login_data.username)
    ).first()
    
    if not user or not user.hashed_password or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username/email or password"
        )
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": create_access_token(user.id, expires_delta=access_token_expires),
        "token_type": "bearer",
    }


@router.post("/google", response_model=Token)
async def google_auth(body: GoogleAuthRequest, db: Session = Depends(get_db)):
    """
    Authenticates a user via Google OAuth2 access token (popup flow) and returns a JWT access token.
    Verifies the token by calling Google's userinfo endpoint.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {body.access_token}"},
                timeout=10.0,
            )
        if response.status_code != 200:
            raise ValueError(f"Google userinfo returned {response.status_code}: {response.text}")
        id_info = response.json()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired Google access token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not verify Google token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = id_info.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google userinfo does not contain an email address."
        )

    name = id_info.get("name") or id_info.get("given_name") or email.split("@")[0]

    user = db.query(User).filter(User.email == email).first()

    if not user:
        # Derive a unique username from the Google display name or email local-part
        base_username = re.sub(r"[^\w]", "", name.lower().replace(" ", "_"))
        if not base_username:
            base_username = email.split("@")[0]

        username = base_username
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}_{counter}"
            counter += 1

        user = User(
            username=username,
            email=email,
            hashed_password=None,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": create_access_token(user.id, expires_delta=access_token_expires),
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Returns profile information for the currently logged-in user.
    """
    return current_user


@router.post("/forgot-password")
def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Initiates a password reset flow.
    Enforces IP and email rate limiting (10/hr per IP, 3/hr per email).
    Always returns the exact same 200 response to prevent email enumeration.
    User lookup and email delivery are handled asynchronously via background task.
    """
    client_ip = _get_client_ip(request)
    normalized_email = body.email.strip().lower()

    # Rate limiting: 10 per IP per hour, 3 per email per hour.
    # Note: attempts are recorded against both IP and email regardless of whether
    # the email corresponds to a registered account.
    ip_allowed = _check_and_record_rate_limit(f"ip:{client_ip}", limit=10, window_seconds=3600)
    email_allowed = _check_and_record_rate_limit(f"email:{normalized_email}", limit=3, window_seconds=3600)

    if not ip_allowed or not email_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later.",
        )

    # Queue background task to look up user and dispatch reset link
    background_tasks.add_task(_process_forgot_password, normalized_email)

    return {"message": "If an account exists for that email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Validates a submitted reset token, hashes it, checks single-use and expiration,
    and updates the user's password within a single atomic transaction.
    """
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()

    token_record = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash)
        .first()
    )

    now = datetime.utcnow()
    # Reject anything unknown, already used, or expired with the exact same 400
    if not token_record or token_record.used_at is not None or token_record.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired.",
        )

    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired.",
        )

    # Update password and mark tokens within a single transaction
    user.hashed_password = get_password_hash(body.new_password)
    token_record.used_at = now

    # Invalidate all other unused tokens for this user
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.id != token_record.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": now})

    db.commit()

    # NOTE: Existing JWT access tokens remain valid until their expiration
    # timestamp because JWTs are stateless. Session revocation (e.g. token blacklisting
    # or token-version tracking) is intentionally not implemented in this step.

    return {"message": "Password updated. You can now log in."}

