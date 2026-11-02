import pytest
import io
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.models import User, Project
from backend.utils.config import settings
from backend.utils.security import get_password_hash, create_access_token
from backend.api.files import reset_upload_limits

@pytest.fixture(autouse=True)
def abuse_settings_reset():
    reset_upload_limits()
    orig_allow_signup = settings.ALLOW_SIGNUP
    orig_max_projects = settings.MAX_PROJECTS_PER_USER
    orig_max_daily_uploads = settings.MAX_DAILY_UPLOADS_PER_USER
    orig_max_daily_mb = settings.MAX_DAILY_UPLOAD_MB_PER_USER

    yield

    settings.ALLOW_SIGNUP = orig_allow_signup
    settings.MAX_PROJECTS_PER_USER = orig_max_projects
    settings.MAX_DAILY_UPLOADS_PER_USER = orig_max_daily_uploads
    settings.MAX_DAILY_UPLOAD_MB_PER_USER = orig_max_daily_mb
    reset_upload_limits()


def create_user(db, username="abuse_user", email="abuse@example.com"):
    user = User(
        id=uuid4(),
        username=username,
        email=email,
        hashed_password=get_password_hash("Password123!"),
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_allow_signup_enabled(client: TestClient):
    settings.ALLOW_SIGNUP = True
    res = client.post("/api/auth/signup", json={
        "username": "user_allow_1",
        "email": "allow1@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 201
    assert res.json()["username"] == "user_allow_1"


def test_allow_signup_disabled(client: TestClient):
    settings.ALLOW_SIGNUP = False
    res = client.post("/api/auth/signup", json={
        "username": "user_disallow_1",
        "email": "disallow1@example.com",
        "password": "Password123!"
    })
    assert res.status_code == 403
    assert "Public registration is currently disabled" in res.json()["detail"]


def test_max_projects_per_user_unlimited(client: TestClient, db):
    settings.MAX_PROJECTS_PER_USER = None
    user = create_user(db, "proj_unlim_user", "unlim@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(4):
        res = client.post("/api/projects", json={"project_name": f"Project {i}"}, headers=headers)
        assert res.status_code == 201


def test_max_projects_per_user_enforced(client: TestClient, db):
    settings.MAX_PROJECTS_PER_USER = 2
    user = create_user(db, "proj_lim_user", "lim@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # 1st and 2nd should pass
    res1 = client.post("/api/projects", json={"project_name": "Project 1"}, headers=headers)
    assert res1.status_code == 201
    res2 = client.post("/api/projects", json={"project_name": "Project 2"}, headers=headers)
    assert res2.status_code == 201

    # 3rd should be blocked
    res3 = client.post("/api/projects", json={"project_name": "Project 3"}, headers=headers)
    assert res3.status_code == 400
    assert "Project limit reached" in res3.json()["detail"]


def test_daily_upload_count_cap_enforced(client: TestClient, db):
    settings.MAX_DAILY_UPLOADS_PER_USER = 2
    settings.MAX_DAILY_UPLOAD_MB_PER_USER = None
    user = create_user(db, "upload_cnt_user", "upload_cnt@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    proj = client.post("/api/projects", json={"project_name": "Upload Proj"}, headers=headers)
    project_id = proj.json()["id"]

    # 1st upload
    f1 = io.BytesIO(b"print('hello 1')\n")
    res1 = client.post(f"/api/projects/{project_id}/files", files={"file": ("test1.py", f1, "text/plain")}, headers=headers)
    assert res1.status_code == 201

    # 2nd upload
    f2 = io.BytesIO(b"print('hello 2')\n")
    res2 = client.post(f"/api/projects/{project_id}/files", files={"file": ("test2.py", f2, "text/plain")}, headers=headers)
    assert res2.status_code == 201

    # 3rd upload -> 429 Too Many Requests
    f3 = io.BytesIO(b"print('hello 3')\n")
    res3 = client.post(f"/api/projects/{project_id}/files", files={"file": ("test3.py", f3, "text/plain")}, headers=headers)
    assert res3.status_code == 429
    assert "Daily upload request limit exceeded" in res3.json()["detail"]


def test_daily_upload_volume_mb_cap_enforced(client: TestClient, db):
    settings.MAX_DAILY_UPLOADS_PER_USER = None
    settings.MAX_DAILY_UPLOAD_MB_PER_USER = 1  # 1 MB
    user = create_user(db, "upload_vol_user", "upload_vol@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    proj = client.post("/api/projects", json={"project_name": "Vol Proj"}, headers=headers)
    project_id = proj.json()["id"]

    # 700 KB -> OK
    f1 = io.BytesIO(b"x = 1\n" * 100000)
    res1 = client.post(f"/api/projects/{project_id}/files", files={"file": ("large1.py", f1, "text/plain")}, headers=headers)
    assert res1.status_code == 201

    # Another 600 KB -> Would exceed 1 MB total -> 429
    f2 = io.BytesIO(b"y = 2\n" * 100000)
    res2 = client.post(f"/api/projects/{project_id}/files", files={"file": ("large2.py", f2, "text/plain")}, headers=headers)
    assert res2.status_code == 429
    assert "Daily upload volume limit exceeded" in res2.json()["detail"]
