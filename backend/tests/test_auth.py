from fastapi.testclient import TestClient

def test_signup_and_login_flow(client: TestClient):
    # 1. Signup a test user
    signup_data = {
        "username": "secdev",
        "email": "secdev@sast.com",
        "password": "supersecurepassword"
    }
    response = client.post("/auth/signup", json=signup_data)
    assert response.status_code == 201
    json_data = response.json()
    assert json_data["username"] == "secdev"
    assert json_data["email"] == "secdev@sast.com"
    assert "id" in json_data
    assert "hashed_password" not in json_data
    
    # 2. Login with credentials
    login_data = {
        "username": "secdev",
        "password": "supersecurepassword"
    }
    response = client.post("/auth/login", json=login_data)
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    access_token = token_data["access_token"]
    
    # 3. Retrieve logged in user profile (/auth/me)
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 200
    me_data = response.json()
    assert me_data["username"] == "secdev"
    assert me_data["email"] == "secdev@sast.com"
    
    # 4. Attempt access without authorization token
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_signup_user_enumeration_parity(client: TestClient):
    """
    Verifies that registration returns the exact same 400 response whether
    a username or an email already exists, preventing account enumeration.
    """
    baseline_user = {
        "username": "enum_target",
        "email": "enum_target@sast.com",
        "password": "Password123!"
    }
    resp0 = client.post("/auth/signup", json=baseline_user)
    assert resp0.status_code == 201

    # 1. Conflict on username only (different email)
    resp_username_conflict = client.post("/auth/signup", json={
        "username": "enum_target",
        "email": "different_email@sast.com",
        "password": "Password123!"
    })
    assert resp_username_conflict.status_code == 400

    # 2. Conflict on email only (different username)
    resp_email_conflict = client.post("/auth/signup", json={
        "username": "different_username",
        "email": "enum_target@sast.com",
        "password": "Password123!"
    })
    assert resp_email_conflict.status_code == 400

    # 3. Conflict on both username and email
    resp_both_conflict = client.post("/auth/signup", json=baseline_user)
    assert resp_both_conflict.status_code == 400

    # Exact parity check: identical JSON structure and detail text
    expected_detail = "An account with this username or email already exists."
    assert resp_username_conflict.json()["detail"] == expected_detail
    assert resp_email_conflict.json()["detail"] == expected_detail
    assert resp_both_conflict.json()["detail"] == expected_detail
    assert resp_username_conflict.json() == resp_email_conflict.json() == resp_both_conflict.json()


def test_jwt_token_version_validation_and_tampering(client: TestClient, db):
    """
    Verifies that get_current_user strictly enforces the token_version claim:
    - Missing token_version -> 401
    - Non-integer types (str, bool, float) -> 401
    - Version mismatch -> 401
    """
    import jwt as pyjwt
    from datetime import datetime, timedelta
    from backend.utils.config import settings
    from backend.models.models import User
    from backend.utils.security import get_password_hash

    # Create user with token_version = 1
    user = User(
        username="jwt_version_test",
        email="jwt_version_test@example.com",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
        token_version=1
    )
    db.add(user)
    db.commit()

    base_exp = datetime.utcnow() + timedelta(hours=1)

    # 1. Missing token_version claim
    token_missing = pyjwt.encode({"sub": str(user.id), "exp": base_exp}, settings.SECRET_KEY, algorithm="HS256")
    resp1 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_missing}"})
    assert resp1.status_code == 401
    assert resp1.json()["detail"] == "Could not validate credentials"

    # 2. String token_version claim
    token_str = pyjwt.encode({"sub": str(user.id), "exp": base_exp, "token_version": "1"}, settings.SECRET_KEY, algorithm="HS256")
    resp2 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_str}"})
    assert resp2.status_code == 401

    # 3. Boolean token_version claim (True)
    token_bool = pyjwt.encode({"sub": str(user.id), "exp": base_exp, "token_version": True}, settings.SECRET_KEY, algorithm="HS256")
    resp3 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_bool}"})
    assert resp3.status_code == 401

    # 4. Float token_version claim
    token_float = pyjwt.encode({"sub": str(user.id), "exp": base_exp, "token_version": 1.0}, settings.SECRET_KEY, algorithm="HS256")
    resp4 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_float}"})
    assert resp4.status_code == 401

    # 5. Outdated / mismatched integer version (e.g. 2 when user is at 1)
    token_mismatch = pyjwt.encode({"sub": str(user.id), "exp": base_exp, "token_version": 2}, settings.SECRET_KEY, algorithm="HS256")
    resp5 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_mismatch}"})
    assert resp5.status_code == 401

    # 6. Valid token_version = 1 succeeds
    token_valid = pyjwt.encode({"sub": str(user.id), "exp": base_exp, "token_version": 1}, settings.SECRET_KEY, algorithm="HS256")
    resp6 = client.get("/auth/me", headers={"Authorization": f"Bearer {token_valid}"})
    assert resp6.status_code == 200
    assert resp6.json()["username"] == "jwt_version_test"
