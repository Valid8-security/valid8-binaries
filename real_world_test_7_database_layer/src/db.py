import sqlite3

def execute_query(query, params=None):
    # CWE-89: SQL Injection
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    if params:
        cursor.execute(query, params)  # Safe
    else:
        cursor.execute(query)  # Unsafe if query contains user input
    return cursor.fetchall()

def search_users(search_term):
    # CWE-89: SQL Injection vulnerability
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)  # SQL injection
    return cursor.fetchall()

def get_user_by_id(user_id):
    # CWE-89: Another SQL injection
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')  # Injection
    return cursor.fetchone()

def insert_log(message):
    # CWE-89: Log injection
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO logs VALUES ('{message}')")  # Injection
    conn.commit()
