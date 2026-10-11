import pytest
from backend.models.models import User, Project, File, Vulnerability
from backend.api.auth import create_access_token
import uuid

def create_test_context(db):
    user = User(
        username="mentor_tester",
        email="mentor_test@example.com",
        hashed_password="fakehash"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        project_name="Security Test Project",
        user_id=user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    file_obj = File(
        project_id=project.id,
        filename="app.py",
        filepath="app.py",
        size=120
    )
    db.add(file_obj)
    db.commit()
    db.refresh(file_obj)

    vuln = Vulnerability(
        file_id=file_obj.id,
        type="SQL Injection",
        line_number=42,
        severity="high",
        description="User input directly concatenated into SQL statement",
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE name = {user_name}')",
        source_tool="bandit"
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)

    token = create_access_token(subject=str(user.id))
    headers = {"Authorization": f"Bearer {token}"}
    return user, vuln, headers

def test_unauthenticated_request_rejected(client):
    res = client.post("/api/ai/ask", json={"question": "What is SQL injection?"})
    assert res.status_code == 401

def test_question_over_2000_chars_rejected(client, db):
    _, _, headers = create_test_context(db)
    long_question = "A" * 2500
    res = client.post("/api/ai/ask", json={"question": long_question}, headers=headers)
    assert res.status_code == 422

def test_general_question_without_vuln_id(client, db):
    _, _, headers = create_test_context(db)
    res = client.post("/api/ai/ask", json={"question": "What is cross-site scripting?"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert isinstance(data["answer"], str)
    assert len(data["answer"]) > 0
    # Ensure no ugly "None" or empty code block leaks
    assert "None" not in data["answer"]
    assert "```\n\n```" not in data["answer"]

def test_question_with_vuln_id(client, db):
    _, vuln, headers = create_test_context(db)
    res = client.post(
        "/api/ai/ask",
        json={"vuln_id": str(vuln.id), "question": "Why is this finding dangerous?"},
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert isinstance(data["answer"], str)
    assert len(data["answer"]) > 0

def test_multiturn_history(client, db):
    _, _, headers = create_test_context(db)
    history = [
        {"role": "user", "content": "What is SQL injection?"},
        {"role": "assistant", "content": "SQL injection occurs when untrusted input is included in SQL queries."},
    ]
    res = client.post(
        "/api/ai/ask",
        json={
            "question": "Can you show me an example in Python?",
            "history": history
        },
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert isinstance(data["answer"], str)

def test_vulnerable_dependency_copilot_context(client, db, monkeypatch):
    from unittest.mock import MagicMock
    from backend.api import ai as ai_module

    user, _, headers = create_test_context(db)
    project = db.query(Project).filter(Project.user_id == user.id).first()

    req_file = File(
        project_id=project.id,
        filename="requirements.txt",
        filepath="requirements.txt",
        size=40
    )
    db.add(req_file)
    db.commit()
    db.refresh(req_file)

    dep_vuln = Vulnerability(
        file_id=req_file.id,
        type="vulnerable_dependency",
        line_number=1,
        severity="high",
        description="Package 'requests' version '2.19.0' in requirements.txt has 1 advisory(s). Recommended version: >= 2.32.0",
        code_snippet="requests==2.19.0",
        suggested_fix="Update requests to >= 2.32.0",
        recommendation=(
            "### Vulnerable Dependency: `requests` (PyPI)\n"
            "- **Installed Version**: `2.19.0`\n\n"
            "#### Known Vulnerabilities (1 advisories)\n"
            "- **[GHSA-j8r2-6x86-q33q](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) (CVE-2023-32681)** [medium]: Proxy-Authorization header leak in requests — Fixed in: `2.31.0`\n"
        ),
        source_tool="osv"
    )
    db.add(dep_vuln)
    db.commit()
    db.refresh(dep_vuln)

    mock_provider = MagicMock()
    mock_provider.ask_question.return_value = "Upgrade requests to 2.32.0."
    monkeypatch.setattr(ai_module, "get_ai_provider", lambda: mock_provider)

    res = client.post(
        "/api/ai/ask",
        json={
            "vuln_id": str(dep_vuln.id),
            "question": "How do I upgrade this safely?"
        },
        headers=headers
    )
    assert res.status_code == 200
    mock_provider.ask_question.assert_called_once()
    call_kwargs = mock_provider.ask_question.call_args[1]
    copilot_context = call_kwargs["full_file_source"]
    assert "requests==2.19.0" in copilot_context
    assert "GHSA-j8r2-6x86-q33q" in copilot_context
    assert "2.31.0" in copilot_context
    assert ">= 2.32.0" in copilot_context
    # Never sends full manifest
    assert "Vulnerable dependency in `requirements.txt`" in copilot_context

