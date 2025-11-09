import hashlib

def hash_password(password):
    # CWE-327: Weak Cryptographic Hash
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash

def authenticate(username, password):
    # CWE-798: Hardcoded Credentials
    if username == 'admin' and password == 'secret123':  # Hardcoded
        return True
    return False
