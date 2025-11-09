
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# IDOR VULNERABILITY: Direct user access without authorization check
@app.route('/user/<user_id>')
def get_user(user_id):
    # VULNERABLE: User can access any user's data by changing user_id
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
    user = cursor.fetchone()
    return jsonify({'user': user})

# IDOR VULNERABILITY: Direct post access
@app.route('/post/<post_id>')
def get_post(post_id):
    # VULNERABLE: No check if user owns the post
    conn = sqlite3.connect('posts.db')
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM posts WHERE id = {post_id}')
    post = cursor.fetchone()
    return jsonify({'post': post})

# SAFE: Proper authorization check
@app.route('/user/profile')
def get_profile():
    user_id = session.get('user_id')  # From session
    if not user_id:
        return jsonify({'error': 'Not logged in'})
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    return jsonify({'user': user})

if __name__ == '__main__':
    app.run()
