"""
vulnerable_test.py -- Intentionally insecure Python file for scanner testing.
Contains: SQL injection, command injection, hardcoded password, pickle deserialization,
          weak MD5 hashing, path traversal, and dangerous eval().
DO NOT deploy this code. For scanner demonstration only.
"""
import subprocess
import pickle
import hashlib
import os
import sqlite3


# 1. Hardcoded credentials
DB_PASSWORD = "supersecret123"
ADMIN_API_KEY = "hardcoded-api-key-do-not-use"


# 2. SQL Injection via string concatenation
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: user input concatenated directly into query string
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# 3. Command Injection via subprocess shell=True
def run_ping(host):
    # VULNERABLE: user-controlled input passed to shell
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


# 4. Insecure pickle deserialization
def load_user_session(session_data):
    # VULNERABLE: arbitrary code execution via malicious pickle payload
    user = pickle.loads(session_data)
    return user


# 5. Weak MD5 hashing for passwords
def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken for passwords
    return hashlib.md5(password.encode()).hexdigest()


# 6. Path traversal
def read_user_file(filename):
    # VULNERABLE: user-controlled path with no sanitization
    base_dir = "/var/app/uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "r") as f:
        return f.read()


# 7. eval() on user input
def calculate(expression):
    # VULNERABLE: arbitrary Python expression execution
    return eval(expression)
