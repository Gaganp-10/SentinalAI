import sqlite3
import subprocess
import pickle
import hashlib

DB_PASSWORD = "admin123"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_backup(filename):
    subprocess.call("tar -czf backup.tar.gz " + filename, shell=True)

def load_session(data):
    return pickle.loads(data)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
