"""
Example vulnerable code for testing Parry scanner
This file contains intentional security vulnerabilities for demonstration
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# CWE-798: Hardcoded Credentials
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdefghijklmnop"

# CWE-89: SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable: String concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# CWE-79: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: Rendering user input without escaping
    html = f"<div>Search results for: {query}</div>"
    return html

# CWE-78: OS Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Vulnerable: Passing user input to shell command
    result = os.system(f"ping -c 1 {host}")
    return str(result)

# CWE-22: Path Traversal
@app.route('/file/<filename>')
def read_file(filename):
    # Vulnerable: No path validation
    with open(filename, 'r') as f:
        return f.read()

# CWE-502: Unsafe Deserialization
@app.route('/load', methods=['POST'])
def load_data():
    data = request.data
    # Vulnerable: Unpickling untrusted data
    obj = pickle.loads(data)
    return str(obj)

# CWE-327: Weak Cryptographic Algorithm
def hash_password(password):
    # Vulnerable: Using MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()

# CWE-918: Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch_url():
    import requests
    url = request.args.get('url', '')
    # Vulnerable: No URL validation
    response = requests.get(url)
    return response.text

# CWE-732: Incorrect Permission Assignment
def create_temp_file():
    temp_file = '/tmp/sensitive.txt'
    with open(temp_file, 'w') as f:
        f.write('sensitive data')
    # Vulnerable: World-writable permissions
    os.chmod(temp_file, 0o777)

if __name__ == '__main__':
    app.run(debug=True)


