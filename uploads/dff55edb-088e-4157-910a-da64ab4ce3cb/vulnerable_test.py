import sqlite3
import subprocess

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # This is a classic SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def run_system_cmd(command):
    # This is a command injection vulnerability
    subprocess.Popen(command, shell=True)
