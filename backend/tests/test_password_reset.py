import pytest
import time
import hashlib
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.utils.security import validate_password_strength, get_password_hash
from backend.models.models import User, PasswordResetToken
from backend.api import auth as auth_module


# ============================================================================
# 1. Unit Tests for validate_password_strength()
# ============================================================================

def test_password_strength_length_boundaries():
    # 7 characters rejected
    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_password_strength("1234567")

    # 8 characters accepted
    assert validate_password_strength("12345678") == "12345678"

    # 72 bytes accepted
    p72 = "a" * 72
    assert len(p72.encode("utf-8")) == 72
    assert validate_password_strength(p72) == p72

    # 73 bytes rejected
    p73 = "a" * 73
    assert len(p73.encode("utf-8")) == 73
    with pytest.raises(ValueError, match="too long"):
        validate_password_strength(p73)


def test_password_strength_multibyte_utf8():
    # 20 emoji characters (each 4 bytes = 80 bytes in UTF-8, but only 20 chars)
    # Must be rejected because UTF-8 byte count exceeds 72 bcrypt limit
    multibyte_pw = "🛡️" * 20  # each is ~6 bytes due to variation selector
    assert len(multibyte_pw.encode("utf-8")) > 72
    with pytest.raises(ValueError, match="too long"):
        validate_password_strength(multibyte_pw)


def test_password_strength_whitespace():
    # Whitespace only
    with pytest.raises(ValueError, match="blank or whitespace only"):
        validate_password_strength("        ")

    with pytest.raises(ValueError, match="blank or whitespace only"):
        validate_password_strength("")


# ============================================================================
# 2. Integration Tests for Signup & Login Validation
# ============================================================================

def test_signup_password_validation_rejection(client: TestClient):
    # Short password rejected with 422
    resp = client.post("/auth/signup", json={
        "username": "shortuser",
        "email": "short@example.com",
        "password": "short"
    })
    assert resp.status_code == 422

    # Password > 72 bytes rejected with 422
    resp = client.post("/auth/signup", json={
        "username": "longuser",
        "email": "long@example.com",
        "password": "x" * 75
    })
    assert resp.status_code == 422


def test_existing_user_with_short_password_can_still_login(client: TestClient, db: Session):
    # Direct DB insertion simulating a legacy account with a 4-char password
    legacy_user = User(
        username="legacyuser",
        email="legacy@example.com",
        hashed_password=get_password_hash("pass"),
        is_active=True
    )
    db.add(legacy_user)
    db.commit()

    # Login MUST succeed (we do not lock out existing users)
    resp = client.post("/auth/login", json={
        "username": "legacyuser",
        "password": "pass"
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


# ============================================================================
# 3. Password Reset Flow: Token Creation, Hashing & Email
# ============================================================================

def test_forgot_password_identical_response(client: TestClient):
    auth_module._reset_rate_limit_records.clear()

    # Unknown email
    resp1 = client.post("/auth/forgot-password", json={"email": "nonexistent@example.com"})
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1 == {"message": "If an account exists for that email, a reset link has been sent."}

    # Known email
    client.post("/auth/signup", json={
        "username": "existinguser",
        "email": "existing@example.com",
        "password": "validpassword123"
    })
    resp2 = client.post("/auth/forgot-password", json={"email": "existing@example.com"})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2 == data1


def test_token_creation_and_hashing(client: TestClient, db: Session, monkeypatch):
    captured_links = []
    monkeypatch.setattr(
        auth_module,
        "send_password_reset_email",
        lambda email, link: captured_links.append((email, link))
    )
    auth_module._reset_rate_limit_records.clear()

    # Create user
    client.post("/auth/signup", json={
        "username": "tokentest",
        "email": "token@example.com",
        "password": "validpassword123"
    })

    resp = client.post("/auth/forgot-password", json={"email": "token@example.com"})
    assert resp.status_code == 200
    assert len(captured_links) == 1

    to_email, link = captured_links[0]
    assert to_email == "token@example.com"
    assert "/reset-password?token=" in link

    raw_token = link.split("token=")[1]
    expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Check DB record
    token_row = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == expected_hash).first()
    assert token_row is not None
    assert token_row.token_hash == expected_hash
    assert token_row.used_at is None
    assert token_row.expires_at > datetime.utcnow()

    # Confirm raw token is nowhere in the DB
    all_tokens = db.query(PasswordResetToken).all()
    for t in all_tokens:
        assert t.token_hash != raw_token


def test_reset_password_single_use(client: TestClient, db: Session, monkeypatch):
    captured_links = []
    monkeypatch.setattr(
        auth_module,
        "send_password_reset_email",
        lambda email, link: captured_links.append((email, link))
    )
    auth_module._reset_rate_limit_records.clear()

    client.post("/auth/signup", json={
        "username": "singleuse",
        "email": "singleuse@example.com",
        "password": "oldpassword123"
    })
    client.post("/auth/forgot-password", json={"email": "singleuse@example.com"})
    raw_token = captured_links[0][1].split("token=")[1]

    # First reset with valid new password
    resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "newpassword123"
    })
    assert resp.status_code == 200
    assert resp.json()["message"] == "Password updated. You can now log in."

    # Old password no longer works
    login_old = client.post("/auth/login", json={"username": "singleuse", "password": "oldpassword123"})
    assert login_old.status_code == 400

    # New password works
    login_new = client.post("/auth/login", json={"username": "singleuse", "password": "newpassword123"})
    assert login_new.status_code == 200

    # Second attempt with same token fails
    resp2 = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "anotherpassword123"
    })
    assert resp2.status_code == 400
    assert resp2.json()["detail"] == "This reset link is invalid or has expired."


def test_invalidation_of_older_tokens(client: TestClient, db: Session, monkeypatch):
    captured_links = []
    monkeypatch.setattr(
        auth_module,
        "send_password_reset_email",
        lambda email, link: captured_links.append((email, link))
    )
    auth_module._reset_rate_limit_records.clear()

    client.post("/auth/signup", json={
        "username": "twotokens",
        "email": "twotokens@example.com",
        "password": "oldpassword123"
    })

    # Request 1
    client.post("/auth/forgot-password", json={"email": "twotokens@example.com"})
    token1 = captured_links[0][1].split("token=")[1]

    # Request 2
    client.post("/auth/forgot-password", json={"email": "twotokens@example.com"})
    token2 = captured_links[1][1].split("token=")[1]

    # Token 1 should be invalidated
    resp1 = client.post("/auth/reset-password", json={
        "token": token1,
        "new_password": "newpassword123"
    })
    assert resp1.status_code == 400
    assert resp1.json()["detail"] == "This reset link is invalid or has expired."

    # Token 2 should work
    resp2 = client.post("/auth/reset-password", json={
        "token": token2,
        "new_password": "newpassword123"
    })
    assert resp2.status_code == 200


def test_token_expiry(client: TestClient, db: Session, monkeypatch):
    captured_links = []
    monkeypatch.setattr(
        auth_module,
        "send_password_reset_email",
        lambda email, link: captured_links.append((email, link))
    )
    auth_module._reset_rate_limit_records.clear()

    client.post("/auth/signup", json={
        "username": "expiryuser",
        "email": "expiry@example.com",
        "password": "oldpassword123"
    })
    client.post("/auth/forgot-password", json={"email": "expiry@example.com"})
    raw_token = captured_links[0][1].split("token=")[1]
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    # Manually backdate expiry in DB
    token_row = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    token_row.expires_at = datetime.utcnow() - timedelta(minutes=5)
    db.commit()

    resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "newpassword123"
    })
    assert resp.status_code == 400
    assert resp.json()["detail"] == "This reset link is invalid or has expired."


def test_rate_limiting(client: TestClient):
    auth_module._reset_rate_limit_records.clear()
    email = "ratelimit@example.com"

    # First 3 attempts succeed (200)
    for _ in range(3):
        resp = client.post("/auth/forgot-password", json={"email": email})
        assert resp.status_code == 200

    # 4th attempt exceeds 3/hr per email
    resp4 = client.post("/auth/forgot-password", json={"email": email})
    assert resp4.status_code == 429
    assert resp4.json()["detail"] == "Too many password reset requests. Please try again later."


def test_google_only_account_password_reset(client: TestClient, db: Session, monkeypatch):
    captured_links = []
    monkeypatch.setattr(
        auth_module,
        "send_password_reset_email",
        lambda email, link: captured_links.append((email, link))
    )
    auth_module._reset_rate_limit_records.clear()

    # Create a user with hashed_password=None (simulating Google sign-in)
    google_user = User(
        username="googleuser",
        email="google@example.com",
        hashed_password=None,
        is_active=True
    )
    db.add(google_user)
    db.commit()

    # Request password reset
    resp = client.post("/auth/forgot-password", json={"email": "google@example.com"})
    assert resp.status_code == 200
    assert len(captured_links) == 1

    raw_token = captured_links[0][1].split("token=")[1]

    # Reset password
    resp = client.post("/auth/reset-password", json={
        "token": raw_token,
        "new_password": "googlenewpass123"
    })
    assert resp.status_code == 200

    # User can now login with password
    login_resp = client.post("/auth/login", json={
        "username": "googleuser",
        "password": "googlenewpass123"
    })
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()
