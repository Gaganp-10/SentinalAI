import sqlite3
import subprocess
import hashlib
import pickle
import os

password = "admin123"

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)

def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def load_data(filename):
    with open(filename, "rb") as f:
        return pickle.loads(f.read())
