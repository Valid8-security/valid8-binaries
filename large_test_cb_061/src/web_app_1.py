import os
import json
from flask import Flask, request

app = Flask(__name__)

def sql_injection_function_0():
    # SQL_INJECTION VULNERABILITY
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "done"

def sql_injection_function_1():
    # SQL_INJECTION VULNERABILITY
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "done"

def sql_injection_function_2():
    # SQL_INJECTION VULNERABILITY
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
