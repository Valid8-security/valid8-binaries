from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

@app.route('/user/<user_id>')
def get_user(user_id):
    # CWE-89: SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)  # SQL injection vulnerability
    return jsonify(cursor.fetchone())

@app.route('/search')
def search():
    # CWE-79: XSS in Flask
    query = request.args.get('q', '')
    return f"<h1>Search results for: {query}</h1>"  # XSS vulnerability

@app.route('/upload', methods=['POST'])
def upload_file():
    # CWE-22: Path Traversal
    filename = request.form.get('filename')
    with open(f'/tmp/{filename}', 'w') as f:  # Path traversal
        f.write(request.form.get('content', ''))
    return 'File uploaded'

@app.route('/run')
def run_command():
    # CWE-78: Command Injection
    cmd = request.args.get('cmd')
    os.system(cmd)  # Command injection
    return 'Command executed'

if __name__ == '__main__':
    app.run(debug=True)
