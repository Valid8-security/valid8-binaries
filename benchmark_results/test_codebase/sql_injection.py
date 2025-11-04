
import sqlite3

def get_user(username):
    # VULNERABLE: SQL Injection
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    return cursor.fetchone()

def get_user_secure(username):
    # SECURE: Parameterized query
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE username = ?"
    cursor = conn.execute(query, (username,))
    return cursor.fetchone()
