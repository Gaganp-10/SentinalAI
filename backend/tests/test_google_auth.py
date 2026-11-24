import time
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from backend.utils.config import settings
from backend.api.auth import reset_auth_rate_limits


@pytest.fixture(autouse=True)
def reset_google_auth_rate_limits():
    reset_auth_rate_limits()
    orig_login_limit = settings.AUTH_RATE_LIMIT_LOGIN_PER_IP
    yield
    settings.AUTH_RATE_LIMIT_LOGIN_PER_IP = orig_login_limit
    reset_auth_rate_limits()


def _mock_tokeninfo_response(payload: dict, status_code: int = 200):
    """Return a mock httpx Response for the tokeninfo endpoint."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = payload
    mock_response.text = "Mock response"
    return mock_response


def test_google_auth_success_new_and_existing_user(client: TestClient):
    mock_payload = {
        "email": "googleuser@example.com",
        "name": "Google User",
        "sub": "google-123456789",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }

    # Patch the httpx.AsyncClient.get call inside the endpoint
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(mock_payload)

        # 1. First sign-in (creates user)
        response = client.post("/auth/google", json={"access_token": "valid_google_access_token"})
        assert response.status_code == 200, response.text
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        access_token = data["access_token"]

    # 2. Check /auth/me with the app JWT
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 200, response.text
    me = response.json()
    assert me["email"] == "googleuser@example.com"
    assert me["username"] == "google_user"

    # 3. Second sign-in with same Google account (should log into existing user, not create duplicate)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(mock_payload)

        response = client.post("/api/auth/google", json={"access_token": "valid_google_access_token_again"})
        assert response.status_code == 200, response.text
        data2 = response.json()
        assert "access_token" in data2

    # 4. Confirm password login fails for OAuth-only user (no hashed_password)
    login_resp = client.post("/auth/login", json={"username": "googleuser@example.com", "password": "anypassword"})
    assert login_resp.status_code == 400


def test_google_auth_invalid_token(client: TestClient):
    """Simulates Google returning a 401 for a bad access token."""
    mock_bad_response = MagicMock()
    mock_bad_response.status_code = 401
    mock_bad_response.text = "Invalid Credentials"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_bad_response

        response = client.post("/auth/google", json={"access_token": "invalid_access_token"})
        assert response.status_code == 401
        assert "Invalid or expired Google access token" in response.json()["detail"]


def test_google_auth_wrong_audience(client: TestClient):
    """Rejects Google token whose audience/azp does not match GOOGLE_CLIENT_ID with generic 401."""
    payload = {
        "email": "victim@example.com",
        "aud": "rogue-attacker-client-id.apps.googleusercontent.com",
        "azp": "rogue-attacker-client-id.apps.googleusercontent.com",
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(payload)
        res = client.post("/api/auth/google", json={"access_token": "wrong_aud_token"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid or expired Google access token."


def test_google_auth_unverified_email(client: TestClient):
    """Rejects Google token with email_verified == false with generic 401."""
    payload = {
        "email": "unverified@example.com",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": False,
        "exp": str(int(time.time()) + 3600),
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(payload)
        res = client.post("/api/auth/google", json={"access_token": "unverified_email_token"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid or expired Google access token."


def test_google_auth_expired(client: TestClient):
    """Rejects expired Google token with generic 401."""
    payload = {
        "email": "expired@example.com",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) - 60),  # expired 60 seconds ago
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(payload)
        res = client.post("/api/auth/google", json={"access_token": "expired_token"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid or expired Google access token."


def test_google_auth_missing_email(client: TestClient):
    """Rejects Google token without email claim with generic 401."""
    payload = {
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(payload)
        res = client.post("/api/auth/google", json={"access_token": "no_email_token"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid or expired Google access token."


def test_google_auth_valid_token(client: TestClient):
    """Accepts valid Google token satisfying all criteria and returns JWT."""
    payload = {
        "email": "valid.google.user@example.com",
        "name": "Valid User",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_tokeninfo_response(payload)
        res = client.post("/api/auth/google", json={"access_token": "valid_token"})
        assert res.status_code == 200
        assert "access_token" in res.json()


def test_google_auth_rate_limiting_blocks_outbound_verification(client: TestClient):
    """
    Verifies Requirement 2:
    - Google auth endpoint enforces IP-based rate limiting before calling Google verification.
    - Subsequent attempts beyond limit return HTTP 429.
    - Outbound token verification is NOT invoked when the limit is exceeded.
    - Sensitive token is not leaked in response detail or logs.
    """
    settings.AUTH_RATE_LIMIT_LOGIN_PER_IP = 2
    ip_headers = {"X-Forwarded-For": "198.51.100.77"}
    secret_token_value = "super-secret-google-oauth-token-12345"

    payload = {
        "email": "ratelimit.test@example.com",
        "name": "Rate Limit Test User",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }

    with patch("backend.api.auth.verify_google_token", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = payload

        # 1. First attempt -> Allowed & calls verify_google_token
        res1 = client.post("/api/auth/google", json={"access_token": secret_token_value}, headers=ip_headers)
        assert res1.status_code == 200
        assert mock_verify.call_count == 1

        # 2. Second attempt -> Allowed & calls verify_google_token
        res2 = client.post("/api/auth/google", json={"access_token": secret_token_value}, headers=ip_headers)
        assert res2.status_code == 200
        assert mock_verify.call_count == 2

        # 3. Third attempt -> Exceeds rate limit (limit=2). Must return 429!
        res3 = client.post("/api/auth/google", json={"access_token": secret_token_value}, headers=ip_headers)
        assert res3.status_code == 429
        assert "Too many login attempts from this IP address" in res3.json()["detail"]

        # CRITICAL: verify_google_token must NOT have been called on the 3rd attempt
        assert mock_verify.call_count == 2, (
            f"Expected verify_google_token to be called 2 times, but called {mock_verify.call_count} times! "
            "Rate limiter must block BEFORE outbound token verification."
        )

        # Confirm sensitive token value is not reflected in error response
        assert secret_token_value not in res3.text


def test_google_auth_fails_if_token_version_is_none(client: TestClient, db, caplog):
    """Verifies that Google auth fails with 500 and an error log if user.token_version is None."""
    import logging
    from backend.models.models import User

    user = User(username="null_tv_user", email="null_tv@example.com", is_active=True)
    db.add(user)
    db.commit()

    payload = {
        "email": "null_tv@example.com",
        "name": "Null TV User",
        "sub": "google-null-tv",
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }

    orig_refresh = db.refresh
    def mock_refresh(instance, *args, **kwargs):
        orig_refresh(instance, *args, **kwargs)
        if isinstance(instance, User) and instance.email == "null_tv@example.com":
            instance.token_version = None

    with patch("backend.api.auth.verify_google_token", new_callable=AsyncMock) as mock_verify, \
         patch.object(db, "refresh", side_effect=mock_refresh):
        mock_verify.return_value = payload
        with caplog.at_level(logging.ERROR):
            res = client.post("/api/auth/google", json={"access_token": "valid_token"})
            assert res.status_code == 500
            assert "User token version is uninitialized" in res.text
            assert "has null token_version" in caplog.text
