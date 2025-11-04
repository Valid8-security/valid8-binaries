"""
Advanced vulnerability test cases for comprehensive recall testing.
This file contains sophisticated vulnerabilities that require advanced detection.
"""

import os
import sys
import pickle
import yaml
import subprocess
import sqlite3
from urllib.parse import urlparse
import requests


# 1. LDAP Injection
def search_user_insecure(username):
    ldap_filter = f"(cn={username})"  # Unsafe LDAP injection
    return ldap_filter


# 2. XPath Injection
def find_user_xpath(username):
    xpath_query = f"//users[@name='{username}']"  # XPath injection
    return xpath_query


# 3. Header Injection
def set_custom_header(value):
    headers = {"Custom-Header": value}  # HTTP header injection
    return headers


# 4. Integer Overflow
def calculate_safety(offset, size):
    result = offset + size  # Potential integer overflow
    return result


# 5. Error Information Disclosure
def process_data(data):
    try:
        result = complex_operation(data)
    except Exception as e:
        print(f"Error: {e}")  # Information disclosure
        return None
    return result


# 6. Improper Certificate Validation
def fetch_data_insecure(url):
    requests.get(url, verify=False)  # Insecure SSL


# 7. Weak Random
def generate_session_id():
    import random
    return random.randint(0, 1000)  # Weak randomness


# 8. Hardcoded Crypto Key
SECRET_KEY = "my-secret-key-12345"  # Hardcoded encryption key


# 9. Missing Encryption
def send_sensitive_data(data):
    # No encryption of sensitive data
    return requests.post("http://api.example.com/data", json=data)


# 10. Cleartext Transmission
def fetch_user_data(user_id):
    response = requests.get(f"http://api.example.com/user/{user_id}")  # HTTP not HTTPS
    return response


# 11. LDAP Injection - Safe variant
def search_user_safe(username):
    import ldap
    username = ldap.filter.escape_filter_chars(username)
    ldap_filter = f"(cn={username})"  # Safe
    return ldap_filter


# 12. Unsafe Deserialization
def load_data(data):
    return pickle.loads(data)  # Unsafe deserialization


# 13. YAML Injection
def parse_config(config_data):
    return yaml.load(config_data)  # YAML injection


# 14. Command Injection with shell
def execute_command(user_input):
    subprocess.call(user_input, shell=True)  # Command injection


# 15. SQL Injection - Second Order
def store_user_query(query):
    # Stored for later execution - second-order SQL injection
    db.execute(f"SELECT * FROM queries WHERE query='{query}'")


# 16. Path Traversal - Advanced
def read_log_file(filename):
    log_dir = "/var/logs/"
    full_path = os.path.join(log_dir, filename)
    return open(full_path).read()  # Path traversal if filename not validated


# 17. Insecure Random - Multiple Issues
def generate_password():
    import random
    import string
    # Predictable random
    random.seed(123)
    return ''.join(random.choice(string.ascii_letters) for _ in range(8))


# 18. Information Exposure Through Directory Listing
def list_directory(path):
    return os.listdir(path)  # Directory traversal exposure


# 19. Insecure Direct Object Reference
def get_user_profile(user_id):
    # No authorization check
    return db.execute(f"SELECT * FROM users WHERE id={user_id}")


# 20. Missing Authentication on Critical Function
def reset_password(username):
    # No authentication required
    db.execute(f"UPDATE users SET password='reset' WHERE username='{username}'")


# 21. Insecure Cookie
def set_cookie_value(cookie_value):
    # No Secure or HttpOnly flags
    return f"Set-Cookie: session={cookie_value}"


# 22. Session Fixation
def login(username, password):
    session_id = "fixed_session_123"  # Session fixation
    return session_id


# 23. Unrestricted Upload
def save_uploaded_file(filename, content):
    # No validation on file type or size
    return open(filename, 'wb').write(content)


# 24. Exposed Dangerous Method
class AdminPanel:
    def execute_system_command(self, cmd):
        # Exposed dangerous method without authorization
        return os.system(cmd)


# 25. Resource Exhaustion
def process_large_list(items):
    # No limits on processing
    results = []
    for item in items:  # Could be millions
        results.append(heavy_computation(item))
    return results


# 26. Race Condition
import threading

shared_resource = 0

def increment_unsafe():
    global shared_resource
    shared_resource += 1  # Race condition


# 27. Double Free / Use After Free (Python memory management)
def manipulate_objects():
    obj1 = []
    obj2 = obj1
    del obj1
    # obj2 still references memory (use after free pattern)


# 28. Out-of-Bounds Read
def read_array_item(data, index):
    return data[index]  # No bounds checking


# 29. Improper Restriction of Operations within the Bounds of a Memory Buffer
def copy_buffer(src, dst, size):
    # No bounds checking
    for i in range(size):
        dst[i] = src[i]


# 30. NULL Pointer Dereference
def process_data_safe(data):
    if data is None:
        return
    # Following code would be NULL dereference in other languages


# Test harness
def complex_operation(data):
    """Placeholder for complex operation"""
    return data.upper()

def heavy_computation(item):
    """Placeholder for heavy computation"""
    return item * 2

# Database connection
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
db.execute("CREATE TABLE queries (id INTEGER, query TEXT)")

