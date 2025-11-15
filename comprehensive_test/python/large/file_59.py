#!/usr/bin/env python3
"""Python test file 59 with vulnerabilities"""

import subprocess
import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

# CWE-78: Command Injection
@app.route('/cmd')
def run_command():
    cmd = request.args.get('cmd', 'ls')
    result = subprocess.call(cmd, shell=True)  # VULNERABLE
    return f"Command executed: {cmd}"

# CWE-79: XSS
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    html = f"<h1>Hello {name}!</h1>"  # VULNERABLE
    return html

# CWE-89: SQL Injection
@app.route('/users')
def get_users():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return str(results)

# CWE-22: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('file', 'default.txt')
    with open(filename, 'r') as f:  # VULNERABLE
        content = f.read()
    return content

if __name__ == '__main__':
    app.run(debug=True)
