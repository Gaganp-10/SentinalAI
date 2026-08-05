import os
import sqlite3
import hashlib
import subprocess
import yaml

# CRITICAL: Hardcoded credentials
SECRET_KEY = "supersecret123"
DB_PASSWORD = "admin123"

def get_user(username, password):
    # HIGH: SQL injection vulnerability
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = conn.execute(query).fetchall()
    return result

def run_command(cmd):
    # CRITICAL: OS command injection
    return subprocess.check_output(cmd, shell=True)

def load_config(path):
    # HIGH: Unsafe YAML load
    with open(path) as f:
        return yaml.load(f)

def hash_password(pwd):
    # MEDIUM: Weak MD5 hash
    return hashlib.md5(pwd.encode()).hexdigest()

def read_file(filename):
    # MEDIUM: Path traversal
    base = "/app/data/"
    return open(base + filename).read()

def debug_info():
    # LOW: Information disclosure
    print("DEBUG: DB_PASSWORD=", DB_PASSWORD)
    print("DEBUG: SECRET_KEY=", SECRET_KEY)
