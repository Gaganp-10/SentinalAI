import pytest
from backend.detectors.schema import Finding
from backend.fixer.fix_generator import generate_template_fix

def test_template_fix_sql_injection_concat():
    finding = Finding(
        file_path="app.py",
        line_number=10,
        type="hardcoded_sql_expressions",
        severity="critical",
        description="SQL injection vulnerability",
        code_snippet='    query = "SELECT * FROM users WHERE username = \'" + username + "\'"'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is True
    assert 'cursor.execute("SELECT * FROM users WHERE username = %s", (username,))' in fix
    assert fix.startswith("    ")  # Indentation preserved

def test_template_fix_sql_injection_fstring():
    finding = Finding(
        file_path="app.py",
        line_number=10,
        type="SQL Injection",
        severity="critical",
        description="SQL injection via f-string",
        code_snippet='    query = f"SELECT * FROM users WHERE username = \'{username}\'"'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is True
    assert 'cursor.execute("SELECT * FROM users WHERE username = %s", (username,))' in fix

def test_template_fix_hardcoded_secret():
    finding = Finding(
        file_path="config.py",
        line_number=5,
        type="hardcoded_password_string",
        severity="high",
        description="Hardcoded password",
        code_snippet='DB_PASSWORD = "admin123"'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is True
    assert fix == 'DB_PASSWORD = os.environ.get("DB_PASSWORD")'

def test_template_fix_shell_equals_true():
    finding = Finding(
        file_path="utils.py",
        line_number=15,
        type="subprocess_popen_with_shell_equals_true",
        severity="high",
        description="subprocess call with shell=True",
        code_snippet='    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is True
    assert 'shell=False' in fix
    assert '["ping", "-c", "1", host]' in fix

def test_template_fix_shell_equals_true_complex_pipe_refuses():
    finding = Finding(
        file_path="utils.py",
        line_number=15,
        type="subprocess_popen_with_shell_equals_true",
        severity="high",
        description="subprocess call with shell=True and pipe",
        code_snippet='    result = subprocess.run("cat /etc/passwd | grep root", shell=True)'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is False

def test_template_fix_weak_hash():
    finding = Finding(
        file_path="auth.py",
        line_number=20,
        type="Weak Hashing Algorithm",
        severity="medium",
        description="MD5 hashing used",
        code_snippet='    return hashlib.md5(password.encode()).hexdigest()'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is True
    assert 'hashlib.sha256(password.encode()).hexdigest()' in fix

def test_template_fix_pickle_loads_refuses():
    finding = Finding(
        file_path="session.py",
        line_number=8,
        type="blacklist",
        severity="high",
        description="pickle.loads usage",
        code_snippet='    user = pickle.loads(session_data)'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is False

def test_template_fix_import_blacklist_refuses():
    finding = Finding(
        file_path="app.py",
        line_number=1,
        type="blacklist",
        severity="low",
        description="Consider security implications of subprocess",
        code_snippet='import subprocess'
    )
    fix, auto_fixable = generate_template_fix(finding)
    assert auto_fixable is False
