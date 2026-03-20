# vuln_demo_api.py
from flask import Flask, request, jsonify
import sqlite3
import os
import os

app = Flask(__name__)

# ------------------------
# Unsafe configuration
# ------------------------
# Example of secrets in code (should never do this in production)
DB_PASSWORD = os.environ.get("DB_PASSWORD", "SuperSecret123")  # Moved to env variable
API_KEY = os.environ.get("API_KEY", "this-is-a-demo-key")  # Moved to env variable

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

    # ⚠️ Vulnerable to SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    conn = get_db_connection()
    user = conn.execute(query, (username, password)).fetchone()  # Use parameterized query
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
    # ⚠️ Unsafe output
    return f"<h1>You said: {msg}</h1>"

# 4. Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # ⚠️ Unsafe use of os.system
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"

# 5. File Disclosure / Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', '')
    try:
        # ⚠️ Unsafe path handling
        with open(os.path.join("files", filename), "r") as f:  # Use os.path.join for safety
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "File not found", 404

# 6. Insecure Deserialization
import pickle
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