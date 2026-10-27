import uuid
import pytest
from backend.models.models import User, Project, File as DBFile, Vulnerability
from backend.utils.security import get_password_hash, create_access_token
from backend.models.schemas import VulnerabilityOut

@pytest.fixture
def auth_context(db):
    user = User(
        email="nofixtest@example.com",
        username="nofixtester",
        hashed_password=get_password_hash("password123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        project_name="No Fix Available Project",
        user_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    db_file = DBFile(
        project_id=project.id,
        filename="app.py",
        filepath="app.py",
        language="python",
        size=100
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, project, db_file, headers


def test_schema_evaluates_no_fix_available_when_fix_equals_snippet():
    """VulnerabilityOut computes no_fix_available=True and auto_fixable=False when suggested_fix == code_snippet."""
    vuln_out = VulnerabilityOut(
        id=uuid.uuid4(),
        file_id=uuid.uuid4(),
        type="eval_used",
        line_number=10,
        severity="high",
        description="Dynamic code execution with eval()",
        code_snippet="result = eval(user_input)\n",
        suggested_fix="  result = eval(user_input)  \n",
        source_tool="bandit",
        fixed=False,
        confidence=1.0,
    )
    assert vuln_out.no_fix_available is True
    assert vuln_out.auto_fixable is False
    assert vuln_out.fix_message == "The provider returned no change"


def test_schema_evaluates_no_fix_available_when_fix_empty():
    """VulnerabilityOut computes no_fix_available=True when suggested_fix is empty string or None."""
    vuln_out = VulnerabilityOut(
        id=uuid.uuid4(),
        file_id=uuid.uuid4(),
        type="eval_used",
        line_number=10,
        severity="high",
        description="Dynamic code execution with eval()",
        code_snippet="result = eval(user_input)\n",
        suggested_fix="",
        source_tool="bandit",
        fixed=False,
        confidence=1.0,
    )
    assert vuln_out.no_fix_available is True
    assert vuln_out.auto_fixable is False


def test_server_side_apply_blocked_for_no_fix_finding(client, auth_context, db, monkeypatch, tmp_path):
    """Server-side Apply must return 422 if finding has no real fix or fix equals snippet."""
    user, project, db_file, headers = auth_context

    from backend.utils.config import settings
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    target_file = project_dir / "app.py"
    target_file.write_text("result = eval(user_input)\n", encoding="utf-8")

    # Finding with eval where suggested_fix is identical to code_snippet
    vuln = Vulnerability(
        file_id=db_file.id,
        type="eval_used",
        line_number=1,
        severity="high",
        description="Dynamic code execution with eval()",
        code_snippet="result = eval(user_input)\n",
        suggested_fix="result = eval(user_input)\n",
        source_tool="bandit",
        fixed=False,
        auto_fixable=False,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    # Attempt to apply fix via API
    resp = client.post(f"/api/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
    assert resp.status_code == 422
    assert "No automatic fix available; review manually" in resp.json()["detail"]
    assert target_file.read_text(encoding="utf-8") == "result = eval(user_input)\n"


def test_regenerate_returns_no_change_when_provider_returns_identical(client, auth_context, db, monkeypatch, tmp_path):
    """Regenerate fix returns no_fix_available=True when generate_patched_code returns the same snippet (provider no-change)."""
    user, project, db_file, headers = auth_context

    from backend.utils.config import settings
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

    project_dir = tmp_path / str(project.id)
    project_dir.mkdir(parents=True, exist_ok=True)
    target_file = project_dir / "app.py"
    target_file.write_text("result = eval(user_input)\n", encoding="utf-8")

    SNIPPET = "result = eval(user_input)\n"

    # Patch generate_patched_code at the source module so the local import inside
    # regenerate_vulnerability_fix picks up the mock (local imports bypass module-attr patching)
    import backend.fixer.fix_generator as fix_gen_module
    monkeypatch.setattr(
        fix_gen_module,
        "generate_patched_code",
        lambda finding, full_code: (full_code, SNIPPET, full_code, False, "template"),
    )

    vuln = Vulnerability(
        file_id=db_file.id,
        type="eval_used",
        line_number=1,
        severity="high",
        description="Dynamic code execution with eval()",
        code_snippet=SNIPPET,
        suggested_fix=None,
        source_tool="bandit",
        fixed=False,
        auto_fixable=False,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    resp = client.post(f"/api/vulnerabilities/{vuln.id}/regenerate-fix", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # VulnerabilityOut.evaluate_fix_state sets no_fix_available=True when fix == snippet
    assert data["no_fix_available"] is True
    assert data["auto_fixable"] is False
    assert data["fix_message"] == "The provider returned no change"
