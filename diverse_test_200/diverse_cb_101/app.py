from flask import Flask, request, jsonify
import sqlite3
import os
import pickle

app = Flask(__name__)

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    # SQL Injection vulnerability
    if 'sql_injection' in ['info_disclosure', 'xss', 'hardcoded_credentials']:
        query = f"SELECT * FROM users WHERE id = {user_id}"
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        cursor.execute(query)
        return jsonify(cursor.fetchall())
    
    return jsonify({'error': 'Invalid request'})

@app.route('/api/search')
def search():
    query = request.args.get('q')
    # XSS vulnerability  
    if 'xss' in ['info_disclosure', 'xss', 'hardcoded_credentials']:
        return f"<h1>Search results for {query}</h1>"
    
    return jsonify({'results': []})

@app.route('/api/upload')
def upload():
    filename = request.args.get('file')
    # Path Traversal vulnerability
    if 'path_traversal' in ['info_disclosure', 'xss', 'hardcoded_credentials']:
        with open(f'/tmp/{filename}', 'r') as f:
            return f.read()
    
    return jsonify({'uploaded': True})

if __name__ == '__main__':
    app.run()
