import os
import sqlite3

def dangerous_code():
    # CWE-78: Command injection
    user_input = input('Enter command: ')
    os.system(user_input)  # Dangerous
    
    # CWE-89: SQL injection  
    query = f"SELECT * FROM users WHERE id = {user_input}"
    conn.execute(query)