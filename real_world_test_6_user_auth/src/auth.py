import hashlib

def authenticate_user(username, password):
    # CWE-798: Hardcoded Credentials
    users = {
        'admin': 'password123',
        'user': 'userpass'
    }
    if username in users and users[username] == password:
        return True
    return False

def hash_password(password):
    # CWE-327: Weak Hash
    return hashlib.md5(password.encode()).hexdigest()

def check_session(session_id):
    # CWE-287: Improper Authentication
    if session_id == 'valid-session':
        return True
    return False

def reset_password(username, new_password):
    # CWE-620: Unverified Password Change
    # No verification that user owns this account
    update_password(username, new_password)
    return True

def update_password(username, new_password):
    # CWE-311: Missing Encryption
    with open(f'{username}_password.txt', 'w') as f:
        f.write(new_password)  # Plaintext storage
