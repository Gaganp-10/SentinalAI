import time
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from backend.utils.config import settings


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
