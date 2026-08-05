import os
import flask
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# CRITICAL: Debug mode enabled in production
app.debug = True

# HIGH: No authentication on admin endpoint
@app.route('/admin/users')
def get_all_users():
    conn = sqlite3.connect("app.db")
    users = conn.execute("SELECT * FROM users").fetchall()
    return jsonify(users)

# MEDIUM: Reflected XSS
@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f"<h1>Results for: {q}</h1>"

# HIGH: JWT secret hardcoded
JWT_SECRET = "changeme"

# LOW: CORS wildcard
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# MEDIUM: Sensitive data in logs
import logging
def log_login(username, password):
    logging.info(f"Login attempt: user={username}, pass={password}")
