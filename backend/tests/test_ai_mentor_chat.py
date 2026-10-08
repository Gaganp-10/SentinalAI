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
