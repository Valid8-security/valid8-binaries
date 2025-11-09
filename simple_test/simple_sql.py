import sqlite3
cursor = sqlite3.connect('db').cursor()
query = f"SELECT * FROM users WHERE id = {input}"
cursor.execute(query)