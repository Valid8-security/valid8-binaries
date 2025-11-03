# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Example vulnerable code for testing Parry scanner
This file contains intentional security vulnerabilities for demonstration

⚠️ WARNING: This code is intentionally vulnerable for testing purposes.
DO NOT use any of these patterns in production code!

Purpose:
- Test Parry's vulnerability detection capabilities
- Demonstrate common security anti-patterns
- Provide examples for security training

Coverage:
- CWE-798: Hardcoded Credentials
- CWE-89: SQL Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-78: OS Command Injection
- CWE-22: Path Traversal
- CWE-502: Unsafe Deserialization
- CWE-327: Weak Cryptography
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-732: Incorrect Permissions

Expected Results:
When scanned with Parry, this file should detect all 9+ vulnerabilities
with high confidence scores.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# CWE-798: Hardcoded Credentials
# VULNERABILITY: Never hardcode sensitive credentials in source code
# FIX: Use environment variables: os.environ.get('DATABASE_PASSWORD')
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdefghijklmnop"

# CWE-89: SQL Injection
# VULNERABILITY: String concatenation in SQL queries allows injection attacks
# Attacker could pass: "1 OR 1=1" to bypass authentication
# FIX: Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable: String concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# CWE-79: Cross-Site Scripting (XSS)
# VULNERABILITY: Rendering unsanitized user input allows JavaScript injection
# Attacker could pass: "<script>alert('XSS')</script>"
# FIX: Use Jinja2 auto-escaping or escape manually: html.escape(query)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: Rendering user input without escaping
    html = f"<div>Search results for: {query}</div>"
    return html

# CWE-78: OS Command Injection
# VULNERABILITY: Passing unvalidated user input to shell commands
# Attacker could pass: "localhost; rm -rf /"
# FIX: Use subprocess with list arguments: subprocess.run(['ping', '-c', '1', host])
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Vulnerable: Passing user input to shell command
    result = os.system(f"ping -c 1 {host}")
    return str(result)

# CWE-22: Path Traversal
# VULNERABILITY: No validation allows reading arbitrary files
# Attacker could pass: "../../etc/passwd"
# FIX: Validate path with os.path.basename() or use whitelist
@app.route('/file/<filename>')
def read_file(filename):
    # Vulnerable: No path validation
    with open(filename, 'r') as f:
        return f.read()

# CWE-502: Unsafe Deserialization
# VULNERABILITY: Unpickling untrusted data can execute arbitrary code
# Pickle can execute malicious code during deserialization
# FIX: Use JSON instead, or validate data source
@app.route('/load', methods=['POST'])
def load_data():
    data = request.data
    # Vulnerable: Unpickling untrusted data
    obj = pickle.loads(data)
    return str(obj)

# CWE-327: Weak Cryptographic Algorithm
# VULNERABILITY: MD5 is cryptographically broken and unsuitable for passwords
# MD5 collisions are trivial to generate
# FIX: Use bcrypt, scrypt, or argon2 for password hashing
def hash_password(password):
    # Vulnerable: Using MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()

# CWE-918: Server-Side Request Forgery (SSRF)
# VULNERABILITY: Unvalidated URL allows attacker to access internal resources
# Attacker could pass: "http://169.254.169.254/latest/meta-data/" (AWS metadata)
# FIX: Validate URL against whitelist, block internal IPs
@app.route('/fetch')
def fetch_url():
    import requests
    url = request.args.get('url', '')
    # Vulnerable: No URL validation
    response = requests.get(url)
    return response.text

# CWE-732: Incorrect Permission Assignment
# VULNERABILITY: File created with overly permissive default permissions
# May be world-readable/writable depending on umask
# FIX: Explicitly set restrictive permissions: os.chmod(temp_file, 0o600)
def create_temp_file():
    temp_file = '/tmp/sensitive.txt'
    with open(temp_file, 'w') as f:
        f.write('sensitive data')
    # Vulnerable: World-writable permissions
    os.chmod(temp_file, 0o777)

if __name__ == '__main__':
    app.run(debug=True)


