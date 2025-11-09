import sqlite3
import yaml
import json

def process_user_data(user_input):
    # CWE-89: SQL Injection in data processing
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO logs VALUES ('{user_input}')")  # SQL injection
    conn.commit()

def load_config(config_file):
    # CWE-502: Unsafe YAML loading
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)  # Safe YAML loading actually
    return config

def save_data(data, filename):
    # CWE-22: Path Traversal in file operations
    with open(filename, 'w') as f:  # No path validation
        json.dump(data, f)

def execute_query(query_template, params):
    # CWE-89: SQL Injection with string formatting
    conn = sqlite3.connect('data.db')
    cursor = conn.cursor()
    full_query = query_template % params  # Vulnerable to injection
    cursor.execute(full_query)
    return cursor.fetchall()
