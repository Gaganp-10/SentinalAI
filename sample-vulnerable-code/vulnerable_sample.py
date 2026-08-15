"""
Sample vulnerable file for demonstrating SentinelAI's detection and
auto-fix capabilities. Intentionally insecure — do not use this code in
a real application.

Upload this file to a new project and run a scan to see:
- SQL injection detection + auto-fixable parameterized query fix
- Hardcoded credential detection + auto-fixable env-var fix
- Command injection detection + auto-fixable shell=False fix
- Insecure deserialization detection (manual-review only, by design)
- Weak hashing detection + auto-fixable sha256 fix
"""
import sqlite3
import subprocess
import pickle
import hashlib

DB_PASSWORD = "admin123"  # hardcoded credential


def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: string concatenation instead of parameterized query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def run_backup(filename):
    # Command Injection: user input passed directly to shell
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)


def load_session(data):
    # Insecure Deserialization
    return pickle.loads(data)


def hash_password(password):
    # Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()