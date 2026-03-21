# vuln_demo_api.py
from flask import Flask, request, jsonify
import sqlite3
import os
import pickle

app = Flask(__name__)

# ------------------------
# Unsafe configuration
# ------------------------
# Example of secrets in code (should never do this in production)
DB_PASSWORD = "SuperSecret123"
API_KEY = "this-is-a-demo-key"

# ------------------------
# Vulnerable database setup
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
# Routes with vulnerabilities
# ------------------------

# 1. SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Fixed SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    conn = get_db_connection()
    user = conn.execute(query, (username, password)).fetchone()
    conn.close()

    if user:
        return jsonify({"message": "Logged in!", "user": dict(user)})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# 2. Exposed .env / secrets
@app.route('/get_secret')
def get_secret():
    # ⚠️ Exposes sensitive API_KEY
    return jsonify({"API_KEY": API_KEY})

# 3. Cross-Site Scripting (XSS)
@app.route('/echo')
def echo():
    msg = request.args.get('msg', '')
    # Fixed XSS vulnerability
    return f"<h1>You said: {msg}</h1>".replace("<", "&lt;").replace(">", "&gt;")

# 4. Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # Fixed Command Injection vulnerability
    result = os.popen(["ping", "-c", "1", host]).read()
    return f"<pre>{result}</pre>"

# 5. File Disclosure / Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', '')
    try:
        # Fixed Path Traversal vulnerability
        safe_path = os.path.join("files", filename)
        with open(safe_path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "File not found", 404

# 6. Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data
    try:
        obj = pickle.loads(data)  # ⚠️ Arbitrary code execution possible
        return jsonify({"message": "Object loaded", "obj": str(obj)})
    except Exception as e:
        return str(e), 400

# 7. CSRF (no protection at all)
@app.route('/change_password', methods=['POST'])
def change_password():
    # ⚠️ No CSRF token, no auth check
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
    app.run(debug=True)