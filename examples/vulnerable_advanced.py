# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Advanced vulnerability test cases for comprehensive recall testing

⚠️ WARNING: This code contains intentionally sophisticated vulnerabilities
to test Parry's advanced detection capabilities. DO NOT use in production!

Purpose:
- Test Parry's deep analysis mode and AI-powered detection
- Demonstrate complex vulnerability patterns beyond basic regex
- Validate detection of less common CWEs
- Benchmark recall against industry tools (Snyk, Semgrep)

Coverage (20+ Advanced CWEs):
- CWE-90: LDAP Injection
- CWE-643: XPath Injection
- CWE-113: HTTP Header Injection
- CWE-190: Integer Overflow
- CWE-209: Information Disclosure via Error Messages
- CWE-295: Improper Certificate Validation
- CWE-330: Use of Insufficiently Random Values
- CWE-321: Hardcoded Cryptographic Key
- CWE-311: Missing Encryption of Sensitive Data
- CWE-319: Cleartext Transmission
- CWE-502: Unsafe Deserialization (pickle)
- CWE-611: XXE via unsafe YAML loading
- CWE-78: Command Injection with shell=True
- CWE-362: Race Conditions (TOCTOU)
- CWE-384: Session Fixation
- CWE-601: Open Redirect
- CWE-770: Resource Exhaustion
- CWE-749: Exposed Dangerous Functions

Expected Results:
- Parry should detect 15+ vulnerabilities in deep mode
- Pattern-based detection may miss some (e.g., LDAP, XPath)
- AI validation should catch context-dependent vulnerabilities
"""

import os
import sys
import pickle
import yaml
import subprocess
import sqlite3
from urllib.parse import urlparse
import requests


# 1. LDAP Injection (CWE-90)
# VULNERABILITY: User input directly embedded in LDAP filter without escaping
# Attacker could pass: "*)(uid=*))(|(uid=*" to bypass authentication
# FIX: Use ldap.filter.escape_filter_chars() to sanitize input
def search_user_insecure(username):
    ldap_filter = f"(cn={username})"  # Unsafe LDAP injection
    return ldap_filter


# 2. XPath Injection (CWE-643)
# VULNERABILITY: Unsanitized input in XPath query
# Attacker could pass: "' or '1'='1" to access unauthorized data
# FIX: Use parameterized XPath queries or sanitize input
def find_user_xpath(username):
    xpath_query = f"//users[@name='{username}']"  # XPath injection
    return xpath_query


# 3. Header Injection (CWE-113)
# VULNERABILITY: User-controlled value in HTTP headers can inject CRLF
# Attacker could pass: "Value\r\nX-Injected: true" to add malicious headers
# FIX: Validate and sanitize header values, reject newlines
def set_custom_header(value):
    headers = {"Custom-Header": value}  # HTTP header injection
    return headers


# 4. Integer Overflow (CWE-190)
# VULNERABILITY: Unchecked arithmetic can overflow and cause buffer overflows
# Large values of offset + size could wrap around to small values
# FIX: Validate bounds before arithmetic operations
def calculate_safety(offset, size):
    result = offset + size  # Potential integer overflow
    return result


# 5. Error Information Disclosure (CWE-209)
# VULNERABILITY: Exception details exposed to users reveal internal structure
# Stack traces can expose file paths, database schemas, code structure
# FIX: Log detailed errors internally, return generic messages to users
def process_data(data):
    try:
        result = complex_operation(data)
    except Exception as e:
        print(f"Error: {e}")  # Information disclosure
        return None
    return result


# 6. Improper Certificate Validation (CWE-295)
# VULNERABILITY: Disabling SSL verification allows man-in-the-middle attacks
# Attacker can intercept and modify traffic
# FIX: Always use verify=True (default), or provide CA bundle
def fetch_data_insecure(url):
    requests.get(url, verify=False)  # Insecure SSL


# 7. Weak Random (CWE-330)
# VULNERABILITY: Predictable random numbers for session IDs
# random.randint is not cryptographically secure
# FIX: Use secrets.token_urlsafe() or os.urandom()
def generate_session_id():
    import random
    return random.randint(0, 1000)  # Weak randomness


# 8. Hardcoded Crypto Key (CWE-321)
# VULNERABILITY: Encryption key hardcoded in source code
# Anyone with access to code can decrypt data
# FIX: Load keys from secure key management system (KMS, vault)
SECRET_KEY = "my-secret-key-12345"  # Hardcoded encryption key


# 9. Missing Encryption (CWE-311)
# VULNERABILITY: Sensitive data transmitted without encryption
# Data sent in plaintext can be intercepted
# FIX: Encrypt data before transmission, or use HTTPS
def send_sensitive_data(data):
    # No encryption of sensitive data
    return requests.post("http://api.example.com/data", json=data)


# 10. Cleartext Transmission (CWE-319)
# VULNERABILITY: Using HTTP instead of HTTPS exposes traffic
# Credentials, session tokens, personal data can be intercepted
# FIX: Use HTTPS URLs exclusively
def fetch_user_data(user_id):
    response = requests.get(f"http://api.example.com/user/{user_id}")  # HTTP not HTTPS
    return response


# 11. LDAP Injection - Safe variant (for comparison)
# This shows the proper way to handle LDAP queries
# escape_filter_chars() prevents LDAP injection attacks
def search_user_safe(username):
    import ldap
    username = ldap.filter.escape_filter_chars(username)
    ldap_filter = f"(cn={username})"  # Safe
    return ldap_filter


# 12. Unsafe Deserialization (CWE-502)
# VULNERABILITY: pickle.loads on untrusted data can execute arbitrary code
# Attacker can craft malicious pickle that runs code during deserialization
# FIX: Use JSON for untrusted data, or verify data source
def load_data(data):
    return pickle.loads(data)  # Unsafe deserialization


# 13. YAML Injection (CWE-611/CWE-502)
# VULNERABILITY: yaml.load() can execute arbitrary Python code
# YAML files can contain !!python/object directives
# FIX: Use yaml.safe_load() instead
def parse_config(config_data):
    return yaml.load(config_data)  # YAML injection


# 14. Command Injection with shell (CWE-78)
# VULNERABILITY: shell=True with user input enables command injection
# Attacker can chain commands with ; && || or use backticks
# FIX: Use shell=False and pass command as list
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

