import sqlite3
import subprocess
import pickle
import hashlib

DB_PASSWORD = os.environ.get("DB_PASSWORD")


def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection: string concatenation instead of parameterized query
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()


def run_backup(filename):
    # Command Injection: user input passed directly to shell
    subprocess.call(["tar", "-czf", "backup.tar.gz", filename], shell=False)


def load_session(data):
    # Insecure Deserialization
    return pickle.loads(data)


def hash_password(password):
    # Weak hashing algorithm
    return hashlib.md5(password.encode()).hexdigest()