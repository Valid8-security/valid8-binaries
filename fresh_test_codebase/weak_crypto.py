import hashlib
def hash_password(password):
    # CWE-327: Weak Cryptographic Algorithm
    return hashlib.md5(password.encode()).hexdigest()