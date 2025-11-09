import hashlib
import random
import string

def hash_password(password):
    # CWE-327: Weak Cryptographic Hash
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # CWE-330: Insufficient Random Values
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(16))  # Weak random

def encrypt_data(data, key):
    # CWE-327: Weak Encryption
    # Using simple XOR 'encryption'
    encrypted = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * len(data)))
    return encrypted

def verify_signature(data, signature):
    # CWE-327: Weak Signature Verification
    expected = hashlib.md5(data.encode()).hexdigest()
    return signature == expected  # No proper signature verification

def generate_key():
    # CWE-798: Hardcoded Cryptographic Key
    return 'hardcoded-key-12345'  # Hardcoded key
