import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # CWE-89: SQL Injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()