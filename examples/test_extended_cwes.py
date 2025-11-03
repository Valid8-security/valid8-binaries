# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Extended CWE test cases for Parry v0.6.0
Tests the newly added CWE detectors beyond the basic OWASP Top 10

⚠️ WARNING: Intentionally vulnerable code for testing purposes only!

Purpose:
- Validate detection of less common but important CWEs
- Test Parry's extended vulnerability coverage
- Ensure recall improvements from v0.5.0 to v0.6.0

Coverage (Additional CWEs):
- CWE-306: Missing Authentication for Critical Function
- CWE-434: Unrestricted File Upload
- CWE-749: Exposed Dangerous Method or Function
- CWE-770: Allocation of Resources Without Limits or Throttling
- CWE-113: HTTP Header Injection (CRLF)
- CWE-209: Generation of Error Message Containing Sensitive Information
- CWE-330: Use of Insufficiently Random Values
- CWE-295: Improper Certificate Validation

Expected Results:
- All functions should trigger vulnerability warnings
- Confidence should be medium to high
- Parry should suggest specific CWE IDs and remediation
"""

import random
import requests

# CWE-306: Missing Authentication
def admin_panel():
    """No authentication decorator"""
    return "Admin panel"

def delete_user(user_id):
    """Dangerous function without auth"""
    pass

def sudo_command(cmd):
    """Sudo function without auth"""
    pass

# CWE-434: Unrestricted File Upload
def upload_file(file):
    """File upload without validation"""
    with open(f"/uploads/{file.filename}", "wb") as f:
        f.write(file.read())  # No validation

def save_uploaded(file):
    """Another upload function"""
    file.save("/tmp/uploads.bin")

# CWE-749: Exposed Dangerous Method (would need Flask context but testing pattern)
def dangerous_eval():
    code = "print('hello')"
    return eval(code)  # Dangerous method

# CWE-770: Resource Exhaustion
def process_all_users(users):
    """Loop without limits"""
    for user in users:  # No limit
        print(user)

def iterate_data(data):
    """Another unlimited loop"""
    for item in data:
        process(item)

# CWE-113: HTTP Header Injection
def set_header(response, request):
    """Header manipulation without CRLF checks"""
    response['Location'] = request.GET.get('redirect', '')  # No validation

# CWE-209: Information Disclosure
def handle_error():
    """Verbose error message"""
    error = "Database connection failed: password=secret123"
    raise ValueError(error)  # Exposed sensitive info!

# CWE-330: Insecure Random
def generate_token():
    """Weak randomness for security"""
    import random
    return random.choice('abcdefghijklmnop')  # Should use secrets module

def create_session_id():
    """Another insecure random"""
    import random
    session_key = random.randint(1, 1000)  # Weak for security
    return session_key

# CWE-295: Improper Certificate Validation
def fetch_https():
    """SSL verification disabled"""
    requests.get('https://example.com', verify=False)  # Dangerous!

def insecure_request():
    """Another verify=False"""
    import ssl
    context = ssl._create_unverified_context()

# CWE-321: Hard-coded Cryptographic Key
def encrypt_data(data):
    """Hardcoded encryption key"""
    key = "my_secret_key_12345abcdefgh"  # Should use environment
    return key

def get_secret_key():
    """Hardcoded secret"""
    SECRET_KEY = "django-insecure-secret-key-here"
    return SECRET_KEY

# CWE-311: Missing Encryption
def store_password(password):
    """Password without encryption"""
    user_password = password  # Plaintext!

def save_api_key(key):
    """API key in plaintext"""
    api_key = key

# CWE-319: Cleartext Transmission
def login(username, password):
    """HTTP instead of HTTPS"""
    requests.post('http://api.example.com/login',
                  json={'user': username, 'pass': password})

def fetch_data(url):
    """Cleartext request"""
    return requests.get('http://example.com/data')

# CWE-90: LDAP Injection
def search_ldap(query):
    """LDAP with concatenation"""
    base_dn = 'ou=users'
    search_filter = '(cn=' + query + ')'  # Concatenated!

# CWE-643: XPath Injection
def search_xml(xpath_query):
    """XPath with concatenation"""
    query = "//user[@name='" + xpath_query + "']"  # Concatenated!

# CWE-384: Session Fixation
def login_user(user):
    """Session ID not regenerated"""
    session['user_id'] = user.id  # Should regenerate

# CWE-362: Race Condition
shared_var = 0

def increment_counter():
    """Race condition on shared resource"""
    global shared_var
    shared_var += 1  # No locking!

def write_shared_file(data):
    """Shared file write"""
    with open('shared.log', 'w') as f:
        f.write(data)  # No locking on shared resource

# CWE-190: Integer Overflow
def calculate_total(items):
    """Arithmetic without bounds"""
    total = 0
    for item in items:
        total += item  # No bounds checking
    return total

def multiply_values(a, request_param):
    """Integer operation"""
    result = a + int(request_param)  # No limit check

# CWE-614: Insecure Cookie
def set_cookie(response, value):
    """Cookie without Secure/HttpOnly"""
    response.set_cookie('session', value)  # Missing flags

def create_cookie(response):
    """Another insecure cookie"""
    response.set_cookie('user_data', 'some_value')

