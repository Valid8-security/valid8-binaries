import hashlib

def hash_password(password):
    # CWE-327: Weak Cryptography
    return hashlib.md5(password.encode()).hexdigest()