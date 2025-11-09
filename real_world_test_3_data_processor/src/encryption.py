import hashlib
import random

def generate_key():
    # CWE-330: Insufficient Random Values
    return str(random.randint(1, 1000))  # Weak random

def hash_data(data):
    # CWE-327: Weak Cryptographic Hash
    return hashlib.sha1(data.encode()).hexdigest()  # Weak hash

def store_credentials(username, password):
    # CWE-311: Missing Encryption
    creds = f'{username}:{password}'  # Plaintext storage
    with open('creds.txt', 'w') as f:
        f.write(creds)
