from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import jwt as pyjwt
from jwt.exceptions import InvalidTokenError as JWTError
from pydantic import ValidationError
import httpx
import re
import secrets
import hashlib
import logging
import time
import threading
import os
import sys
import ipaddress

from backend.database.session import get_db, SessionLocal
from backend.models.models import User, PasswordResetToken
from backend.models.schemas import (
    UserCreate,
    UserOut,
    Token,
    LoginRequest,
    GoogleAuthRequest,
    DeletionConfirmationRequest,
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
_login_failures: dict[tuple[str, str], list[float]] = {}

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

def reset_auth_rate_limits():
    """Helper for unit tests to reset in-memory auth rate limit state."""
    with _reset_rate_limit_lock:
        _reset_rate_limit_records.clear()
        _login_failures.clear()

def get_trusted_proxy_networks() -> list:
    """
    Parses and returns the configured trusted proxy CIDR networks.
    """
    raw = settings.TRUSTED_PROXIES
    items = raw if isinstance(raw, list) else [p.strip() for p in str(raw).split(",") if p.strip()]
    networks = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                networks.append(ipaddress.ip_network(f"{item}/32" if ":" not in item else f"{item}/128", strict=False))
        except ValueError as e:
            logger.warning("Invalid trusted proxy CIDR configured: %r: %s", item, e)
    return networks

def _get_client_ip(request: Request) -> str:
    """
    Extracts and validates the client IP address.
    Strictly verifies that the direct socket peer belongs to TRUSTED_PROXIES
    before inspecting X-Forwarded-For. If the connecting peer is untrusted,
    X-Forwarded-For is ignored completely and the verified peer IP is returned.
    Validates all forwarded addresses with Python's ipaddress module.
    """
    is_test_env = (
        settings.ENV != "production"
        and (
            settings.ENV == "development"
            or os.getenv("TESTING") == "1"
            or "pytest" in sys.modules
            or bool(os.getenv("PYTEST_CURRENT_TEST"))
        )
    )

    peer_host = request.client.host if request.client else None

    # Handle Starlette TestClient explicitly for test-only compatibility
    # Never treat testclient as a trusted production proxy
    if peer_host == "testclient":
        if is_test_env:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                raw_forwarded = forwarded.strip()
                if not raw_forwarded or "," in raw_forwarded:
                    logger.warning("Unexpected multi-value or comma-formatted X-Forwarded-For in testclient: %r. Falling back to loopback.", forwarded)
                    return "127.0.0.1"
                try:
                    ipaddress.ip_address(raw_forwarded)
                    return raw_forwarded
                except ValueError:
                    return "127.0.0.1"
            return "127.0.0.1"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid client socket peer address."
            )

    if not peer_host:
        if is_test_env:
            return "127.0.0.1"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot establish client connection address."
        )

    try:
        peer_addr = ipaddress.ip_address(peer_host)
        if isinstance(peer_addr, ipaddress.IPv6Address) and peer_addr.ipv4_mapped:
            peer_addr = peer_addr.ipv4_mapped
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid socket peer address."
        )

    trusted_nets = get_trusted_proxy_networks()
    is_trusted = any(peer_addr in net for net in trusted_nets)

    # 1. If peer is UNTRUSTED: ignore forwarded headers entirely and return peer_addr
    if not is_trusted:
        return str(peer_addr)

    # 2. If peer is TRUSTED: parse X-Forwarded-For
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        # Trusted proxy connected without X-Forwarded-For: fall back to the proxy's IP itself
        return str(peer_addr)

    raw_forwarded = forwarded.strip()
    if not raw_forwarded:
        return str(peer_addr)

    # Caddy strictly overwrites X-Forwarded-For with {remote_host} (a single client IP).
    # Commas indicate multi-value or empty-segment malformed formatting (e.g. "ip,", ",ip", "ip, ip").
    # Empty segments, multiple values, and unexpected formatting must not be silently normalized.
    if "," in raw_forwarded:
        logger.warning(
            "Unexpected multi-value or comma-formatted X-Forwarded-For from trusted proxy %s: %r. Falling back to proxy IP.",
            peer_addr,
            forwarded,
        )
        return str(peer_addr)

    try:
        client_addr = ipaddress.ip_address(raw_forwarded)
        if isinstance(client_addr, ipaddress.IPv6Address) and client_addr.ipv4_mapped:
            client_addr = client_addr.ipv4_mapped
        return str(client_addr)
    except ValueError:
        # Malformed/unparseable forwarded IP:
        # Do NOT fall back to shared loopback rate-limit identity for real requests!
        # Use the verified peer IP.
        logger.warning(
            "Trusted proxy %s sent invalid X-Forwarded-For IP %r. Using verified peer IP.",
            peer_addr,
            raw_forwarded,
        )
        return str(peer_addr)

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
        payload = pyjwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["exp", "sub"]},
        )
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        import uuid
        try:
            user_id = uuid.UUID(user_id_str)
        except ValueError:
            raise credentials_exception

        raw_token_version = payload.get("token_version")
        if raw_token_version is None or type(raw_token_version) is not int or raw_token_version < 1:
            raise credentials_exception
    except (JWTError, ValidationError):
        raise credentials_exception
        
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    user_token_version = getattr(user, "token_version", 1) or 1
    if raw_token_version != user_token_version:
        raise credentials_exception
    return user


@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def signup(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    """
    Registers a new user account.
    """
    if not settings.ALLOW_SIGNUP:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is currently disabled."
        )

    client_ip = _get_client_ip(request)
    if not _check_and_record_rate_limit(f"signup:ip:{client_ip}", limit=settings.AUTH_RATE_LIMIT_SIGNUP_PER_IP, window_seconds=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signup attempts from this IP address. Please try again later."
        )

    norm_username = user_in.username.strip().lower()
    norm_email = user_in.email.strip().lower()
    if not _check_and_record_rate_limit(f"signup:account:{norm_username}", limit=settings.AUTH_RATE_LIMIT_SIGNUP_PER_ACCOUNT, window_seconds=3600) or \
       not _check_and_record_rate_limit(f"signup:account:{norm_email}", limit=settings.AUTH_RATE_LIMIT_SIGNUP_PER_ACCOUNT, window_seconds=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signup attempts for this account. Please try again later."
        )

    # Check if username or email exists (unified check to prevent account enumeration)
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this username or email already exists."
        )

    try:
        db_user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=get_password_hash(user_in.password),
            is_active=True,
            token_version=1
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this username or email already exists."
        )


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticates a user via JSON request body and returns a JWT access token.
    Enforces IP-based and Account-based rate limits alongside progressive exponential delay
    keyed on (account, IP) for repeated failures.
    """
    client_ip = _get_client_ip(request)
    norm_account = login_data.username.strip().lower()

    # 1. IP-level rate limiting
    if not _check_and_record_rate_limit(f"login:ip:{client_ip}", limit=settings.AUTH_RATE_LIMIT_LOGIN_PER_IP, window_seconds=300):
        logger.warning("Rate limit exceeded for IP %s: too many login attempts", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts from this IP address. Please try again later."
        )

    # 2. Account-level rate limiting across multiple IPs
    if not _check_and_record_rate_limit(f"login:account:{norm_account}", limit=settings.AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT, window_seconds=300):
        logger.warning("Rate limit exceeded for account '%s' from IP %s", norm_account, client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts for this account. Please try again later."
        )

    # 3. Progressive delay keyed on (account, IP)
    now = time.time()
    with _reset_rate_limit_lock:
        fail_history = [ts for ts in _login_failures.get((norm_account, client_ip), []) if ts > now - 900]
        if fail_history:
            fail_count = len(fail_history)
            if fail_count >= 3:
                delay = min(60.0, 2.0 ** (fail_count - 3))
                elapsed = now - fail_history[-1]
                if elapsed < delay:
                    remaining = delay - elapsed
                    logger.warning(
                        "Progressive delay active for account '%s' from IP '%s' (failure count %d). Remaining wait: %.1fs",
                        norm_account, client_ip, fail_count, remaining
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many failed login attempts. Progressive delay active. Please wait {int(remaining) + 1} seconds before trying again."
                    )

    # Find user by username or email
    user = db.query(User).filter(
        (User.username == login_data.username) | (User.email == login_data.username)
    ).first()
    
    if not user or not user.hashed_password or not verify_password(login_data.password, user.hashed_password):
        with _reset_rate_limit_lock:
            cur = [ts for ts in _login_failures.get((norm_account, client_ip), []) if ts > now - 900]
            cur.append(now)
            _login_failures[(norm_account, client_ip)] = cur
            fail_count = len(cur)
        logger.warning(
            "Login failed for account '%s' from IP '%s' (consecutive failures: %d)",
            norm_account, client_ip, fail_count
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username/email or password"
        )

    # Reset failure tracking on successful login
    with _reset_rate_limit_lock:
        _login_failures.pop((norm_account, client_ip), None)
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    user_token_version = getattr(user, "token_version", 1) or 1
    return {
        "access_token": create_access_token(
            user.id,
            expires_delta=access_token_expires,
            token_version=user_token_version
        ),
        "token_type": "bearer",
    }


async def verify_google_token(token: str) -> dict:
    """
    Verifies a Google OAuth access token or ID token via Google's tokeninfo endpoint.
    Strictly enforces:
      - aud or azp == settings.GOOGLE_CLIENT_ID
      - email_verified is true
      - token is not expired (exp > now or expires_in > 0)
      - valid email is present
    Raises a generic 401 on any failure to prevent token probing.
    """
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token},
                timeout=10.0,
            )
            if resp.status_code != 200:
                resp = await client.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"id_token": token},
                    timeout=10.0,
                )
        if resp.status_code != 200:
            raise ValueError(f"tokeninfo returned HTTP {resp.status_code}")

        data = resp.json()
        email = data.get("email")
        if not email or not isinstance(email, str) or "@" not in email:
            raise ValueError("missing or invalid email")

        aud = data.get("aud")
        azp = data.get("azp")
        expected_client_id = settings.GOOGLE_CLIENT_ID
        if not (aud == expected_client_id or azp == expected_client_id):
            raise ValueError("audience mismatch")

        email_verified = data.get("email_verified")
        if email_verified not in (True, "true", "True"):
            raise ValueError("unverified email")

        now = time.time()
        if "exp" in data:
            if float(data["exp"]) <= now:
                raise ValueError("token expired")
        elif "expires_in" in data:
            if float(data["expires_in"]) <= 0:
                raise ValueError("token expired")

        return data
    except Exception as e:
        logger.warning("Google token verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/google", response_model=Token)
async def google_auth(body: GoogleAuthRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticates a user via Google OAuth2 token and returns a JWT access token.
    Enforces IP-based rate limiting before outbound Google token verification.
    Strictly verifies audience (aud/azp == GOOGLE_CLIENT_ID), verified email, and expiration.
    """
    client_ip = _get_client_ip(request)
    if not _check_and_record_rate_limit(f"login:ip:{client_ip}", limit=settings.AUTH_RATE_LIMIT_LOGIN_PER_IP, window_seconds=300):
        logger.warning("Rate limit exceeded for IP %s: too many Google auth attempts", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts from this IP address. Please try again later."
        )

    id_info = await verify_google_token(body.access_token)

    email = id_info["email"]
    name = id_info.get("name") or id_info.get("given_name") or email.split("@")[0]

    user = db.query(User).filter(User.email == email).first()

    if not user:
        if not settings.ALLOW_SIGNUP:
            allowlist = [e.strip().lower() for e in settings.GOOGLE_AUTH_ALLOWLIST.split(",") if e.strip()]
            user_email_lower = email.strip().lower()
            is_allowed = (user_email_lower in allowlist) or any(
                user_email_lower.endswith(f"@{domain.lstrip('@')}") for domain in allowlist if domain.startswith("@")
            )
            if not is_allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Public registration is disabled and this Google account is not on the authorized allowlist."
                )

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

    db.refresh(user)
    if user.token_version is None:
        logger.error("User %s has null token_version", user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User token version is uninitialized."
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return {
        "access_token": create_access_token(
            user.id,
            expires_delta=access_token_expires,
            token_version=user.token_version
        ),
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Returns profile information for the currently logged-in user.
    """
    return current_user


@router.delete("/me", status_code=status.HTTP_200_OK)
async def delete_account(
    request: Request,
    password: Optional[str] = None,
    google_token: Optional[str] = None,
    confirmation: Optional[DeletionConfirmationRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Permanently deletes the current user's account, all associated projects,
    scans, findings, and disk upload directories.
    Requires password confirmation for password accounts, or a fresh Google token for OAuth accounts.
    Builds disk paths only from validated UUIDs inside the upload root without following symlinks.
    """
    import shutil
    import os
    import uuid

    # Read confirmation from JSON body, query params, or custom confirmation header
    confirm_pw = (confirmation.password if confirmation else None) or password or request.headers.get("x-confirm-password")
    confirm_google = (confirmation.google_token if confirmation else None) or google_token or request.headers.get("x-confirm-google-token")

    if current_user.hashed_password:
        if not confirm_pw or not verify_password(confirm_pw, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password confirmation."
            )
    else:
        if not confirm_google:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Fresh Google token required for account deletion."
            )
        token_data = await verify_google_token(confirm_google)
        if token_data.get("email", "").lower() != current_user.email.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token does not match the account email."
            )

    upload_root = os.path.realpath(os.path.abspath(settings.UPLOAD_DIR))
    for project in current_user.projects:
        proj_uuid = uuid.UUID(str(project.id))
        project_dir = os.path.realpath(os.path.join(upload_root, str(proj_uuid)))
        if os.path.dirname(project_dir) == upload_root and os.path.exists(project_dir):
            if os.path.islink(project_dir):
                os.unlink(project_dir)
            elif os.path.isdir(project_dir):
                shutil.rmtree(project_dir, ignore_errors=True)

    db.delete(current_user)
    db.commit()
    return {"detail": "Account and all associated projects and files permanently deleted."}


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

    # Update password and increment token_version within a single transaction to revoke active sessions
    user.hashed_password = get_password_hash(body.new_password)
    user.token_version = (getattr(user, "token_version", 1) or 1) + 1
    token_record.used_at = now

    # Invalidate all other unused tokens for this user
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.id != token_record.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": now})

    db.commit()

    # NOTE: Existing JWT access tokens are immediately invalidated because user.token_version
    # has been incremented. Any subsequent request with an old JWT fails with HTTP 401.

    return {"message": "Password updated. You can now log in."}

