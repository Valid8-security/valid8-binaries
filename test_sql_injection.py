from flask import request
import sqlite3
conn = sqlite3.connect('db')
cursor = conn.cursor()
user_id = request.args.get('id')
cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')