from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient


def _mock_userinfo_response(payload: dict):
    """Return a mock httpx Response for the userinfo endpoint."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = payload
    return mock_response


def test_google_auth_success_new_and_existing_user(client: TestClient):
    mock_payload = {
        "email": "googleuser@example.com",
        "name": "Google User",
        "sub": "google-123456789",
    }

    # Patch the httpx.AsyncClient.get call inside the endpoint
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = _mock_userinfo_response(mock_payload)

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
        mock_get.return_value = _mock_userinfo_response(mock_payload)

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
