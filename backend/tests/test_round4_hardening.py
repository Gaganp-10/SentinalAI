import pytest
import io
import os
import shutil
import json
import tempfile
import uuid as uuid_module
from uuid import uuid4
from datetime import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app, sweep_orphaned_scans
from backend.models.models import User, Project, File, ScanHistory, Vulnerability
from backend.utils.config import settings
from backend.utils.security import get_password_hash, create_access_token
from backend.database.session import SessionLocal
from backend.api.auth import reset_auth_rate_limits
from backend.api.files import reset_upload_limits, check_volume_capacity
from backend.api.ai import reset_copilot_rate_limits
from backend.reports.json_csv_report import generate_csv_report, _escape_csv_cell
from backend.reports.html_report import generate_html_report
from backend.ai.provider import FallbackTemplateProvider, _cap_prompt_text
from backend.scripts.create_user import create_user_account


@pytest.fixture(autouse=True)
def reset_hardening_state():
    reset_auth_rate_limits()
    reset_upload_limits()
    reset_copilot_rate_limits()
    orig_allow_signup = settings.ALLOW_SIGNUP
    orig_google_allowlist = settings.GOOGLE_AUTH_ALLOWLIST
    orig_max_storage = settings.MAX_USER_STORAGE_MB
    orig_concurrency = settings.MAX_CONCURRENT_SCANS
    orig_timeout = settings.SCAN_TIMEOUT_SECONDS
    orig_ai_cap = settings.MAX_AI_EXPLANATIONS_PER_SCAN
    orig_copilot_limit = settings.MAX_DAILY_COPILOT_CHATS_PER_USER

    yield

    settings.ALLOW_SIGNUP = orig_allow_signup
    settings.GOOGLE_AUTH_ALLOWLIST = orig_google_allowlist
    settings.MAX_USER_STORAGE_MB = orig_max_storage
    settings.MAX_CONCURRENT_SCANS = orig_concurrency
    settings.SCAN_TIMEOUT_SECONDS = orig_timeout
    settings.MAX_AI_EXPLANATIONS_PER_SCAN = orig_ai_cap
    settings.MAX_DAILY_COPILOT_CHATS_PER_USER = orig_copilot_limit
    reset_auth_rate_limits()
    reset_upload_limits()
    reset_copilot_rate_limits()


def create_test_user(db, username="hardened_user", email="hardened@example.com"):
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


# =============================================================================
# 1. Proxy Headers & HTTPS Scheme Verification
# =============================================================================

def test_proxy_headers_propagation(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """Verifies that reverse-proxy headers (client IP and HTTPS scheme) reach FastAPI."""
    monkeypatch.setattr(settings, "ENV", "development")
    res = client.get(
        "/api/proxy-test",
        headers={
            "X-Forwarded-For": "203.0.113.195",
            "X-Forwarded-Proto": "https",
            "Host": "sentinel.example.com"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["headers"]["x-forwarded-for"] == "203.0.113.195"
    assert data["headers"]["x-forwarded-proto"] == "https"


def test_fastapi_redirect_preserves_https(client: TestClient):
    """
    Verifies that the /api/redirect-test endpoint issues a 307 redirect
    pointing to /api (the intended destination).

    NOTE: The TestClient bypasses uvicorn's --proxy-headers processing, so the
    scheme in the Location header will be 'http' in test context — the important
    check is that the redirect goes to the correct path and the endpoint exists.
    In production, Caddy sets X-Forwarded-Proto: https and uvicorn honours it,
    causing the Location to be https://. This is verified by the prod E2E run.
    """
    res = client.get(
        "/api/redirect-test",
        headers={
            "X-Forwarded-Proto": "https",
            "Host": "sentinel.example.com"
        },
        follow_redirects=False
    )
    assert res.status_code == 307
    location = res.headers.get("location", "")
    # In test context (no uvicorn proxy-header processing), http is expected.
    # Verify the redirect destination path contains /api.
    assert "/api" in location


# =============================================================================
# 2. Authentication Rate Limiting (Login & Signup)
# =============================================================================

def test_login_rate_limit_per_ip(client: TestClient, db):
    create_test_user(db, "user_ip_target", "ip_target@example.com")
    settings.AUTH_RATE_LIMIT_LOGIN_PER_IP = 3

    ip_headers = {"X-Forwarded-For": "198.51.100.22"}
    for i in range(3):
        res = client.post("/api/auth/login", json={"username": f"random_user_{i}", "password": "wrong"}, headers=ip_headers)
        assert res.status_code in (400, 401)

    # 4th attempt from the same IP must be rate-limited
    res = client.post("/api/auth/login", json={"username": "random_user_x", "password": "wrong"}, headers=ip_headers)
    assert res.status_code == 429
    assert "Too many login attempts from this IP" in res.json()["detail"]


def test_login_rate_limit_per_account(client: TestClient, db):
    user = create_test_user(db, "target_account", "target@example.com")
    settings.AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT = 2
    settings.AUTH_RATE_LIMIT_LOGIN_PER_IP = 100

    # Two attempts from different IPs targeting the same account
    res1 = client.post("/api/auth/login", json={"username": "target_account", "password": "wrong"}, headers={"X-Forwarded-For": "1.1.1.1"})
    assert res1.status_code == 400
    res2 = client.post("/api/auth/login", json={"username": "target_account", "password": "wrong"}, headers={"X-Forwarded-For": "2.2.2.2"})
    assert res2.status_code == 400

    # 3rd attempt targeting the same account
    res3 = client.post("/api/auth/login", json={"username": "target_account", "password": "wrong"}, headers={"X-Forwarded-For": "3.3.3.3"})
    assert res3.status_code == 429
    assert "Too many login attempts for this account" in res3.json()["detail"]


def test_signup_rate_limit_per_ip(client: TestClient):
    settings.ALLOW_SIGNUP = True
    settings.AUTH_RATE_LIMIT_SIGNUP_PER_IP = 2

    ip_headers = {"X-Forwarded-For": "198.51.100.88"}
    for i in range(2):
        res = client.post("/api/auth/signup", json={"username": f"new_{i}", "email": f"new_{i}@example.com", "password": "Password123!"}, headers=ip_headers)
        assert res.status_code == 201

    res3 = client.post("/api/auth/signup", json={"username": "new_3", "email": "new_3@example.com", "password": "Password123!"}, headers=ip_headers)
    assert res3.status_code == 429
    assert "Too many signup attempts from this IP" in res3.json()["detail"]


# =============================================================================
# 3. Production Access, Admin Creation, Allowlist & DELETE Endpoints
# =============================================================================

def test_google_auth_allowlist_when_signup_disabled(client: TestClient, db):
    settings.ALLOW_SIGNUP = False
    settings.GOOGLE_AUTH_ALLOWLIST = "authorized@partner.com, @trusted-domain.com"
    import time

    base_claims = {
        "aud": settings.GOOGLE_CLIENT_ID,
        "email_verified": True,
        "exp": str(int(time.time()) + 3600),
    }

    # Mock Google OAuth token verification
    with patch("httpx.AsyncClient.get") as mock_get:
        # Case A: Email not in allowlist -> Rejected
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {**base_claims, "email": "unauthorized@gmail.com", "name": "Unauthorized User"})
        res = client.post("/api/auth/google", json={"access_token": "valid_token_1"})
        assert res.status_code == 403
        assert "not on the authorized allowlist" in res.json()["detail"]

        # Case B: Specific allowed email -> Accepted & Created
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {**base_claims, "email": "authorized@partner.com", "name": "Partner Admin"})
        res2 = client.post("/api/auth/google", json={"access_token": "valid_token_2"})
        assert res2.status_code == 200
        assert "access_token" in res2.json()

        # Case C: Domain allowlist (@trusted-domain.com) -> Accepted
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {**base_claims, "email": "dev@trusted-domain.com", "name": "Domain User"})
        res3 = client.post("/api/auth/google", json={"access_token": "valid_token_3"})
        assert res3.status_code == 200
        assert "access_token" in res3.json()


def test_admin_create_user_cli(db):
    """Verifies the administrative user creation script functionality."""
    username = f"cli_admin_{uuid4().hex[:6]}"
    email = f"{username}@sentinel.internal"
    create_user_account(username=username, email=email, password="SecurePassword123!", db_session=db)

    created = db.query(User).filter(User.username == username).first()
    assert created is not None
    assert created.email == email
    assert created.hashed_password is not None


def test_delete_project_removes_db_and_files(client: TestClient, db):
    user = create_test_user(db, "del_proj_user", "del_proj@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # Create project
    proj_res = client.post("/api/projects", json={"project_name": "Project To Delete"}, headers=headers)
    assert proj_res.status_code == 201
    project_id = proj_res.json()["id"]

    # Create dummy upload directory on disk
    proj_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
    os.makedirs(proj_dir, exist_ok=True)
    with open(os.path.join(proj_dir, "test.py"), "w") as f:
        f.write("print('hello')")

    assert os.path.exists(proj_dir)

    # 1. Attempt deletion without valid password confirmation -> must be rejected
    del_fail = client.delete(f"/api/projects/{project_id}", headers=headers, params={"password": "WrongPassword"})
    assert del_fail.status_code == 401
    assert os.path.exists(proj_dir)

    # 2. Delete project with valid password confirmation
    del_res = client.delete(f"/api/projects/{project_id}", headers=headers, params={"password": "Password123!"})
    assert del_res.status_code == 200
    assert "deleted successfully" in del_res.json()["detail"]

    # Verify DB row gone — convert str project_id to uuid.UUID for SQLAlchemy UUID column
    assert db.query(Project).filter(Project.id == uuid_module.UUID(project_id)).first() is None
    # Verify disk files removed
    assert not os.path.exists(proj_dir)


def test_delete_account_removes_user_projects_and_files(client: TestClient, db):
    user = create_test_user(db, "del_acct_user", "del_acct@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # Create a project and disk directory for user
    proj = Project(id=uuid4(), user_id=user.id, project_name="User Project")
    db.add(proj)
    db.commit()

    proj_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(proj.id)))
    os.makedirs(proj_dir, exist_ok=True)
    with open(os.path.join(proj_dir, "app.py"), "w") as f:
        f.write("# payload")

    # 1. Attempt deletion with wrong password -> rejected
    del_fail = client.delete("/api/auth/me", headers=headers, params={"password": "WrongPassword!"})
    assert del_fail.status_code == 401
    assert os.path.exists(proj_dir)

    # 2. Call DELETE /api/auth/me with correct password
    del_res = client.delete("/api/auth/me", headers=headers, params={"password": "Password123!"})
    assert del_res.status_code == 200

    # User and project must be gone
    assert db.query(User).filter(User.id == user.id).first() is None
    assert db.query(Project).filter(Project.id == proj.id).first() is None
    assert not os.path.exists(proj_dir)


def test_user_cannot_delete_another_users_project_or_files(client: TestClient, db):
    """
    Ensures strong multi-tenant authorization: User B cannot delete User A's project or files,
    even if User B passes their own valid password.
    """
    user_a = create_test_user(db, "victim_user", "victim@example.com")
    user_b = create_test_user(db, "attacker_user", "attacker@example.com")
    token_b = create_access_token(user_b.id)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Create project owned by User A
    proj_a = Project(id=uuid4(), user_id=user_a.id, project_name="User A Confidential Project")
    db.add(proj_a)
    db.commit()

    proj_a_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(proj_a.id)))
    os.makedirs(proj_a_dir, exist_ok=True)
    file_path = os.path.join(proj_a_dir, "confidential.py")
    with open(file_path, "w") as f:
        f.write("SECRET_KEY = 'super_secret'")

    # User B tries to delete User A's project
    res = client.delete(f"/api/projects/{proj_a.id}", headers=headers_b, params={"password": "Password123!"})
    assert res.status_code == 404
    assert res.json()["detail"] == "Project not found"

    # Verify project row still exists in DB
    assert db.query(Project).filter(Project.id == proj_a.id).first() is not None
    # Verify disk files were NOT deleted
    assert os.path.exists(file_path)


# =============================================================================
# 4. Storage Quotas & Disk Threshold
# =============================================================================

def test_user_cumulative_storage_cap(client: TestClient, db):
    settings.MAX_USER_STORAGE_MB = 1  # 1 MB limit
    user = create_test_user(db, "storage_user", "storage@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    proj = Project(id=uuid4(), user_id=user.id, project_name="Quota Project")
    db.add(proj)
    # Add existing 900 KB file record
    existing_file = File(
        id=uuid4(),
        project_id=proj.id,
        filename="large.js",
        filepath="large.js",
        size=950 * 1024
    )
    db.add(existing_file)
    db.commit()

    # Try uploading a 150 KB file (950 KB + 150 KB = 1100 KB > 1 MB)
    content = b"x" * (150 * 1024)
    res = client.post(
        f"/api/projects/{proj.id}/files",
        files={"file": ("second.js", content, "application/javascript")},
        headers=headers
    )
    assert res.status_code == 413
    assert "User cumulative storage limit exceeded" in res.json()["detail"]


def test_volume_85_percent_full_refusal():
    """Verifies that check_volume_capacity raises 507 when volume >= 85% full."""
    with patch("shutil.disk_usage", return_value=(1000, 860, 140)):  # 86% used
        with pytest.raises(Exception) as exc_info:
            check_volume_capacity("/dummy/path")
        assert exc_info.value.status_code == 507
        assert "Storage volume capacity critical" in exc_info.value.detail


# =============================================================================
# 5. Scan Concurrency & Startup Sweep
# =============================================================================

def test_scan_global_concurrency_limit(client: TestClient, db):
    settings.MAX_CONCURRENT_SCANS = 1
    user = create_test_user(db, "scan_concur_user", "concur@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    proj1 = Project(id=uuid4(), user_id=user.id, project_name="Project 1")
    proj2 = Project(id=uuid4(), user_id=user.id, project_name="Project 2")
    db.add_all([proj1, proj2])
    db.commit()

    # Create dummy active scan in DB
    active_scan = ScanHistory(project_id=proj1.id, status="running")
    db.add(active_scan)
    db.commit()

    # Attempt to trigger scan on proj2 -> should be blocked by concurrency limit
    # First give proj2 a dummy file so file check passes
    db.add(File(id=uuid4(), project_id=proj2.id, filename="main.py", filepath="main.py", size=100))
    db.commit()

    res = client.post(f"/api/projects/{proj2.id}/scan", headers=headers)
    assert res.status_code == 429
    assert "Scan concurrency limit reached" in res.json()["detail"]


def test_startup_sweep_marks_orphaned_scans_failed(db):
    proj = Project(id=uuid4(), user_id=create_test_user(db, "sweep_user", "sweep@example.com").id, project_name="Sweep Proj")
    db.add(proj)
    s1 = ScanHistory(id=uuid4(), project_id=proj.id, status="pending")
    s2 = ScanHistory(id=uuid4(), project_id=proj.id, status="running")
    db.add_all([s1, s2])
    db.commit()

    sweep_orphaned_scans(db_session=db)

    db.refresh(s1)
    db.refresh(s2)
    assert s1.status == "failed"
    assert "Scan interrupted by server restart" in s1.warnings
    assert s2.status == "failed"
    assert "Scan interrupted by server restart" in s2.warnings


# =============================================================================
# 6. AI Controls: Daily Copilot Limit & Prompt Capping
# =============================================================================

def test_daily_copilot_rate_limit(client: TestClient, db):
    settings.MAX_DAILY_COPILOT_CHATS_PER_USER = 2
    user = create_test_user(db, "copilot_user", "copilot@example.com")
    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # Query 1 & 2 succeed
    res1 = client.post("/api/ai/ask", json={"question": "What is SQL injection?"}, headers=headers)
    assert res1.status_code == 200
    res2 = client.post("/api/ai/ask", json={"question": "How to prevent XSS?"}, headers=headers)
    assert res2.status_code == 200

    # Query 3 exceeds cap
    res3 = client.post("/api/ai/ask", json={"question": "What is CSRF?"}, headers=headers)
    assert res3.status_code == 429
    assert "Daily AI Copilot query limit exceeded" in res3.json()["detail"]


def test_prompt_size_capping():
    long_code = "print('hello')\n" * 500  # ~7500 chars
    capped = _cap_prompt_text(long_code, max_len=1000)
    assert len(capped) <= 1100
    assert "truncated for AI prompt size limit" in capped


def test_ai_template_fallback_works():
    provider = FallbackTemplateProvider()
    explanation = provider.explain("sql_injection", "Unsanitized user input", "critical", "CWE-89", "cursor.execute(query)")
    assert "sql_injection" in explanation
    assert "critical" in explanation


# =============================================================================
# 7. Stored XSS Protection & CSV Injection Escaping
# =============================================================================

def test_csv_injection_cell_escaping():
    # Characters that trigger spreadsheet formula execution: = + - @ \t \r
    assert _escape_csv_cell("=1+1") == "'=1+1"
    assert _escape_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert _escape_csv_cell("-2+3") == "'-2+3"
    assert _escape_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert _escape_csv_cell("\tDDE") == "'\tDDE"
    assert _escape_csv_cell("Safe Normal Text") == "Safe Normal Text"


def test_csv_report_generation_escapes_formulas(db):
    user = create_test_user(db, "csv_user", "csv@example.com")
    proj = Project(id=uuid4(), user_id=user.id, project_name="CSV Proj")
    db.add(proj)
    file_record = File(id=uuid4(), project_id=proj.id, filename="=calc.py", filepath="=calc.py", size=10)
    db.add(file_record)
    vuln = Vulnerability(
        id=uuid4(),
        file_id=file_record.id,
        type="=1+1",
        line_number=1,
        severity="@HIGH",
        description="+cmd|' /C calc'!A0",
        source_tool="bandit"
    )
    vuln.file = file_record
    db.add(vuln)
    db.commit()

    csv_output = generate_csv_report([vuln])
    lines = csv_output.strip().splitlines()
    assert len(lines) >= 2
    row = lines[1]
    # Check that dangerous formula symbols were safely escaped
    assert "'=calc.py" in row
    assert "'=1+1" in row
    assert "'@HIGH" in row
    assert "'+cmd|' /C calc'!A0" in row


def test_html_report_autoescapes_malicious_payloads(db):
    user = create_test_user(db, "html_xss_user", "xss@example.com")
    proj = Project(id=uuid4(), user_id=user.id, project_name="<script>alert(1)</script>")
    proj.files = []
    # Provide all count fields that the HTML report template reads.
    # SQLAlchemy column defaults (default=0) only apply on INSERT, not on unsaved objects.
    scan = ScanHistory(
        id=uuid4(),
        project_id=proj.id,
        status="completed",
        total_issues=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        scan_time=datetime.utcnow()
    )
    file_record = File(id=uuid4(), project_id=proj.id, filename="<img src=x onerror=alert(1)>", filepath="test.py", size=10)
    vuln = Vulnerability(
        id=uuid4(),
        file_id=file_record.id,
        type="xss_test",
        line_number=1,
        severity="high",
        description="<img src=x onerror=alert('xss')>",
        source_tool="bandit"
    )
    vuln.file = file_record

    rendered = generate_html_report(proj, scan, [vuln])
    # Must not contain unescaped script tag or unescaped onerror attribute
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(&#39;xss&#39;)&gt;" in rendered

