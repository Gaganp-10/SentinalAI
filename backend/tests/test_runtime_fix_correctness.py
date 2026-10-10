import os
import ast
import tempfile
import uuid
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.fixer.fix_runtime import detect_sql_placeholder, add_import_if_missing, get_new_undefined_names
from backend.fixer.fix_generator import generate_template_fix, generate_patched_code
from backend.models.models import Vulnerability, User, Project, File
from backend.database.session import SessionLocal
from backend.utils.security import get_password_hash, create_access_token
from backend.utils.config import settings

client = TestClient(app)

def test_missing_import_added_once():
    """Test that import os is added once when missing, and not duplicated if already present."""
    code_without_import = '"""Module docstring"""\nDB_PASS = "admin123"\n'
    patched_1 = add_import_if_missing(code_without_import, "os", "import os")
    assert "import os" in patched_1
    assert patched_1.count("import os") == 1
    # Check placement: after docstring
    assert patched_1.startswith('"""Module docstring"""\nimport os\n')

    # Now run again on code that already imports os
    patched_2 = add_import_if_missing(patched_1, "os", "import os")
    assert patched_2.count("import os") == 1
    assert patched_2 == patched_1

    # Also test 'from os import environ' prevents 'import os'
    code_with_from = 'from os import environ\nDB_PASS = "admin123"\n'
    patched_3 = add_import_if_missing(code_with_from, "os", "import os")
    assert "import os" not in patched_3
    assert patched_3 == code_with_from

def test_sql_placeholder_driver_detection():
    """Test SQL placeholder detection based on imported database driver."""
    # sqlite3 -> ?
    sqlite_code = "import sqlite3\ndef query(uid):\n    return 'SELECT * FROM users WHERE id = ' + uid\n"
    ph, drv = detect_sql_placeholder(sqlite_code)
    assert ph == "?"
    assert drv == "sqlite3"

    # from sqlite3 import connect -> ?
    sqlite_from_code = "from sqlite3 import connect\ndef query(uid):\n    pass\n"
    ph, drv = detect_sql_placeholder(sqlite_from_code)
    assert ph == "?"
    assert drv == "sqlite3"

    # psycopg2 -> %s
    pg_code = "import psycopg2\ndef query(uid):\n    return 'SELECT * FROM users WHERE id = ' + uid\n"
    ph, drv = detect_sql_placeholder(pg_code)
    assert ph == "%s"
    assert drv == "psycopg2"

    # pymysql -> %s
    mysql_code = "import pymysql\ndef query(uid):\n    pass\n"
    ph, drv = detect_sql_placeholder(mysql_code)
    assert ph == "%s"
    assert drv == "pymysql"

    # mysql.connector -> %s
    mysql_conn_code = "import mysql.connector\ndef query(uid):\n    pass\n"
    ph, drv = detect_sql_placeholder(mysql_conn_code)
    assert ph == "%s"
    assert drv == "mysql"

    # unknown driver / no driver -> None
    generic_code = "def query(uid):\n    return 'SELECT * FROM users WHERE id = ' + uid\n"
    ph, drv = detect_sql_placeholder(generic_code)
    assert ph is None

    # ORM like sqlalchemy -> None
    orm_code = "from sqlalchemy import create_engine\ndef query(uid):\n    pass\n"
    ph, drv = detect_sql_placeholder(orm_code)
    assert ph is None

def test_template_fix_sql_injection_sqlite():
    """SQL fix on sqlite3 file uses '?' placeholder and is auto_fixable."""
    finding = SimpleNamespace(
        type="SQL Injection",
        line_number=3,
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        cwe_id="CWE-89",
    )
    sqlite_file = 'import sqlite3\ndef get_user(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    suggested_fix, auto_fixable = generate_template_fix(finding, file_content=sqlite_file)
    assert auto_fixable is True
    assert 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))' in suggested_fix

def test_template_fix_sql_injection_psycopg2():
    """SQL fix on psycopg2 file uses '%s' placeholder and is auto_fixable."""
    finding = SimpleNamespace(
        type="SQL Injection",
        line_number=3,
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        cwe_id="CWE-89",
    )
    pg_file = 'import psycopg2\ndef get_user(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    suggested_fix, auto_fixable = generate_template_fix(finding, file_content=pg_file)
    assert auto_fixable is True
    assert 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))' in suggested_fix

def test_template_fix_sql_injection_unknown_driver():
    """SQL fix on unknown-driver file marks auto_fixable=False with explanatory note."""
    finding = SimpleNamespace(
        type="SQL Injection",
        line_number=2,
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        cwe_id="CWE-89",
        recommendation=None
    )
    unknown_file = 'def get_user(cursor, user_id):\n    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    suggested_fix, auto_fixable = generate_template_fix(finding, file_content=unknown_file)
    assert auto_fixable is False
    assert "depends on the database driver" in finding.recommendation

def test_undefined_name_detection():
    """Verify get_new_undefined_names catches newly introduced undefined names."""
    orig = "def foo():\n    return 42\n"
    patched_valid = "import os\ndef foo():\n    return os.environ.get('KEY')\n"
    assert get_new_undefined_names(orig, patched_valid) == set()

    patched_bad = "def foo():\n    return non_existent_variable + 1\n"
    assert "non_existent_variable" in get_new_undefined_names(orig, patched_bad)

    # Preexisting undefined name in original code should not be flagged as new
    orig_with_warning = "def foo():\n    return legacy_var\n"
    patched_same_warning = "import os\ndef foo():\n    x = os.environ.get('KEY')\n    return legacy_var\n"
    assert get_new_undefined_names(orig_with_warning, patched_same_warning) == set()

def test_generate_patched_code_adds_import_os():
    """generate_patched_code adds import os when secret fix is generated."""
    finding = SimpleNamespace(
        type="Hardcoded Password",
        line_number=2,
        code_snippet='DB_PASSWORD = "secret123"',
        cwe_id="CWE-798",
        file_path="config.py",
    )
    orig_file = '# Config file\nDB_PASSWORD = "secret123"\n'
    patched, _, _, auto_fixable, _ = generate_patched_code(finding, orig_file)
    assert auto_fixable is True
    assert "import os" in patched
    assert "os.environ.get(\"DB_PASSWORD\"" in patched
    # Valid syntax and no new undefined names
    ast.parse(patched)
    assert get_new_undefined_names(orig_file, patched) == set()

def test_apply_fix_blocks_undefined_names_via_endpoint(tmp_path, monkeypatch):
    """Verify apply-fix endpoint returns 422 if patched source introduces undefined names."""
    db = SessionLocal()
    try:
        user = User(
            username=f"fix_tester_{uuid.uuid4().hex[:6]}",
            email=f"fixtest_{uuid.uuid4().hex[:6]}@example.com",
            hashed_password=get_password_hash("password123")
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(str(user.id))
        headers = {"Authorization": f"Bearer {token}"}

        project = Project(user_id=user.id, project_name="Fix Runtime Test")
        db.add(project)
        db.commit()
        db.refresh(project)

        project_dir = tmp_path / str(project.id)
        project_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path))

        filename = "compute.py"
        full_path = project_dir / filename
        original_code = "def compute(x):\n    return x * 2\n"
        full_path.write_text(original_code, encoding="utf-8")

        f_rec = File(
            project_id=project.id,
            filename=filename,
            filepath=filename,
            language="python",
            size=len(original_code.encode("utf-8"))
        )
        db.add(f_rec)
        db.commit()
        db.refresh(f_rec)

        vuln = Vulnerability(
            file_id=f_rec.id,
            type="Logic Flaw",
            line_number=2,
            severity="medium",
            description="Bad compute",
            code_snippet="return x * 2",
            cwe_id="CWE-20",
            source_tool="manual",
            auto_fixable=True,
            suggested_fix="return undefined_symbol_123 * 2"
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)

        # Attempt to apply fix through API
        response = client.post(f"/vulnerabilities/{vuln.id}/apply-fix", headers=headers)
        assert response.status_code == 422
        data = response.json()
        assert "undefined name" in data["detail"]
        assert "undefined_symbol_123" in data["detail"]
    finally:
        db.close()
