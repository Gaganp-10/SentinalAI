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
