import os
import shutil
import tempfile
import pytest
from uuid import uuid4
from backend.models.models import User, Project, File as DBFile, Vulnerability
from backend.utils.security import get_password_hash, create_access_token
from backend.utils.config import settings

@pytest.fixture
def auth_setup(db):
    user = User(
        username="fix_tester",
        email="fixtest@example.com",
        hashed_password=get_password_hash("password123")
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        user_id=user.id,
        project_name="Fix Test Project"
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    token = create_access_token(str(user.id))
    headers = {"Authorization": f"Bearer {token}"}
    return user, project, headers


def test_apply_fix_and_download_flow(client, db, auth_setup, tmp_path, monkeypatch):
    user, project, headers = auth_setup
    
    # Override settings.UPLOAD_DIR to tmp_path
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))
    
    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)

    filename = "vulnerable_app.py"
    filepath = "vulnerable_app.py"
    full_path = project_dir / filename

    original_code = (
        "import sqlite3\n\n"
        "def query_user(user_input):\n"
        "    conn = sqlite3.connect('test.db')\n"
        "    cursor = conn.cursor()\n"
        "    query = f\"SELECT * FROM users WHERE username = '{user_input}'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )

    full_path.write_text(original_code, encoding="utf-8")

    db_file = DBFile(
        project_id=project.id,
        filename=filename,
        filepath=filepath,
        language="python",
        size=len(original_code.encode("utf-8"))
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    vuln_code_snippet = "query = f\"SELECT * FROM users WHERE username = '{user_input}'\"\n    cursor.execute(query)"
    vuln_suggested_fix = "query = \"SELECT * FROM users WHERE username = ?\"\n    cursor.execute(query, (user_input,))"

    vuln = Vulnerability(
        file_id=db_file.id,
        type="sql_injection",
        line_number=5,
        severity="critical",
        description="Possible SQL Injection",
        code_snippet=vuln_code_snippet,
        suggested_fix=vuln_suggested_fix,
        source_tool="ast",
        fixed=False
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    # 1. Apply fix
    resp = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["vulnerability"]["id"] == str(vuln.id)
    assert data["vulnerability"]["fixed"] is True
    assert data["file"]["id"] == str(db_file.id)

    # Check file on disk actually changed
    updated_disk_content = full_path.read_text(encoding="utf-8")
    assert vuln_suggested_fix in updated_disk_content
    assert vuln_code_snippet not in updated_disk_content
    assert data["file"]["size"] == len(updated_disk_content.encode("utf-8"))

    # 2. Download file content
    download_resp = client.get(f"/files/{db_file.id}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.content == full_path.read_bytes()

    # 3. Apply fix a second time -> Should return 409 Conflict
    reapply_resp = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert reapply_resp.status_code == 409
    assert "already marked as fixed" in reapply_resp.json()["detail"]


def test_apply_fix_zero_occurrences_conflict(client, db, auth_setup, tmp_path, monkeypatch):
    user, project, headers = auth_setup
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    full_path = project_dir / "modified_app.py"

    content = "print('Hello World')\n"
    full_path.write_text(content, encoding="utf-8")

    db_file = DBFile(
        project_id=project.id,
        filename="modified_app.py",
        filepath="modified_app.py",
        language="python",
        size=len(content)
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    vuln = Vulnerability(
        file_id=db_file.id,
        type="hardcoded_secret",
        line_number=1,
        severity="high",
        description="Hardcoded Secret",
        code_snippet="secret = '12345'",
        suggested_fix="secret = os.getenv('SECRET')",
        source_tool="semgrep",
        fixed=False
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    resp = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 409
    assert "Could not locate the original code" in resp.json()["detail"]
    assert full_path.read_text(encoding="utf-8") == content


def test_apply_fix_multiple_occurrences_conflict(client, db, auth_setup, tmp_path, monkeypatch):
    user, project, headers = auth_setup
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    full_path = project_dir / "duplicate_app.py"

    code_snippet = "exec(user_input)"
    content = f"def a(user_input):\n    {code_snippet}\n\ndef b(user_input):\n    {code_snippet}\n"
    full_path.write_text(content, encoding="utf-8")

    db_file = DBFile(
        project_id=project.id,
        filename="duplicate_app.py",
        filepath="duplicate_app.py",
        language="python",
        size=len(content)
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    vuln = Vulnerability(
        file_id=db_file.id,
        type="eval_use",
        line_number=2,
        severity="critical",
        description="Use of exec",
        code_snippet=code_snippet,
        suggested_fix="# Exec removed",
        source_tool="ast",
        fixed=False
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    resp = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 409
    assert "appears multiple times in the file" in resp.json()["detail"]
    assert full_path.read_text(encoding="utf-8") == content


def test_unauthorized_access(client, db, auth_setup):
    _, _, headers = auth_setup
    # Create another user and vulnerability
    other_user = User(
        username="other_user",
        email="other@example.com",
        hashed_password=get_password_hash("password123")
    )
    db.add(other_user)
    db.commit()

    other_project = Project(user_id=other_user.id, project_name="Other Project")
    db.add(other_project)
    db.commit()

    other_file = DBFile(
        project_id=other_project.id,
        filename="secret.py",
        filepath="secret.py",
        language="python",
        size=10
    )
    db.add(other_file)
    db.commit()

    other_vuln = Vulnerability(
        file_id=other_file.id,
        type="secret",
        line_number=1,
        severity="high",
        description="Secret",
        code_snippet="foo",
        suggested_fix="bar",
        source_tool="ast",
        fixed=False
    )
    db.add(other_vuln)
    db.commit()

    # Attempt to apply fix by user 1 on user 2's vulnerability -> 404
    resp = client.post(f"/vulnerabilities/{other_vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 404

    # Attempt to download file by user 1 on user 2's file -> 404
    resp_dl = client.get(f"/files/{other_file.id}/download", headers=headers)
    assert resp_dl.status_code == 404


def test_apply_fix_not_auto_fixable_returns_422(client, db, auth_setup, tmp_path, monkeypatch):
    user, project, headers = auth_setup
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    full_path = project_dir / "import_app.py"

    content = "import subprocess\n"
    full_path.write_text(content, encoding="utf-8")

    db_file = DBFile(
        project_id=project.id,
        filename="import_app.py",
        filepath="import_app.py",
        language="python",
        size=len(content)
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    vuln = Vulnerability(
        file_id=db_file.id,
        type="blacklist",
        line_number=1,
        severity="low",
        description="Consider possible security implications associated with the subprocess module",
        code_snippet="import subprocess",
        suggested_fix="import subprocess",
        source_tool="bandit",
        fixed=False,
        auto_fixable=False
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    resp = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 422
    assert "doesn't have an automatically-applicable fix" in resp.json()["detail"]
    assert full_path.read_text(encoding="utf-8") == content

