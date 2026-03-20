# vuln_demo_api.py
from flask import Flask, request, jsonify
import sqlite3
import os
import html
import json
import subprocess
import re

app = Flask(__name__)

# ------------------------
# Configuration (use environment variables in production)
# ------------------------
DB_PASSWORD = os.environ.get("DB_PASSWORD", "change-me")
API_KEY = os.environ.get("API_KEY", "change-me")

# ------------------------
# Database setup
# ------------------------
def get_db_connection():
    conn = sqlite3.connect('demo.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB
conn = get_db_connection()
conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
conn.execute('INSERT OR IGNORE INTO users (id, username, password) VALUES (1, "admin", "password")')
conn.commit()
conn.close()

# ------------------------
# Routes with security fixes
# ------------------------

# 1. SQL Injection - FIXED: Use parameterized queries
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Fixed: parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    conn = get_db_connection()
    user = conn.execute(query, (username, password)).fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Logged in!", "user": dict(user)})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# 2. Exposed secrets - FIXED: removed direct exposure
@app.route('/get_secret')
def get_secret():
    return jsonify({"message": "Access denied"}), 403

# 3. Cross-Site Scripting (XSS) - FIXED: use html.escape
@app.route('/echo')
def echo():
    msg = request.args.get('msg', '')
    safe_msg = html.escape(msg)
    return f"<h1>You said: {safe_msg}</h1>"

# 4. Command Injection - FIXED: use subprocess with argument list
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # Validate input: only allow hostnames and IPs
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        return "Invalid host", 400
    try:
        result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
        return f"<pre>{html.escape(result.stdout)}</pre>"
    except subprocess.TimeoutExpired:
        return "Timeout", 408

# 5. File Disclosure / Path Traversal - FIXED: validate path
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', '')
    base_dir = os.path.realpath('./files')
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    # Prevent path traversal
    if not full_path.startswith(base_dir):
        return "Access denied", 403
    try:
        with open(full_path, "r") as f:
            return f"<pre>{html.escape(f.read())}</pre>"
    except FileNotFoundError:
        return "File not found", 404

# 6. Insecure Deserialization - FIXED: use JSON instead of pickle
@app.route('/deserialize', methods=['POST'])
def deserialize():
    try:
        obj = json.loads(request.data)
        return jsonify({"message": "Object loaded", "obj": str(obj)})
    except Exception as e:
        return str(e), 400

# 7. CSRF - Added basic auth check
@app.route('/change_password', methods=['POST'])
def change_password():
    auth = request.headers.get('Authorization')
    if not auth:
        return jsonify({"message": "Unauthorized"}), 401
    new_password = request.form.get('password', '')
    conn = get_db_connection()
    conn.execute("UPDATE users SET password=? WHERE id=1", (new_password,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password changed"})

# ------------------------
# Run server
# ------------------------
if __name__ == "__main__":
    app.run(debug=False)
