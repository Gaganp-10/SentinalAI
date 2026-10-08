from datetime import datetime, timedelta
from typing import Any, Union
from jose import jwt
import bcrypt
from backend.utils.config import settings


def validate_password_strength(password: str) -> str:
    """
    Shared password validator used by the signup and reset-password schemas.

    Rules (kept consistent with the frontend UX):
      - At least 8 characters
      - Not whitespace-only
      - At most 72 UTF-8 bytes (bcrypt's hard limit — count bytes so that
        multibyte characters and emoji are handled correctly)

    Returns the password unchanged if valid; raises ValueError otherwise.
    The caller is responsible for catching this in a Pydantic field_validator.
    """
    if not password or password.strip() == "":
        raise ValueError("Password must not be blank or whitespace only.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password.encode("utf-8")) > 72:
        raise ValueError(
            "Password is too long. Use at most 72 bytes when encoded as UTF-8 "
            "(fewer characters are needed when using multibyte characters or emoji)."
        )
    return password

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a hashed password using bcrypt.
    """
    try:
        password_bytes = plain_password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    """
    Hashes a password string using bcrypt.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")

def create_access_token(subject: Union[str, Any], expires_delta: timedelta = None) -> str:
    """
    Encodes subject and expiration time into a signed JWT.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt
