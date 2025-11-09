import os
import hashlib
import pickle

# Weak crypto
if 'weak_crypto' in ['xss', 'command_injection', 'idor', 'path_traversal', 'weak_crypto', 'auth_bypass', 'xxe']:
    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()

# Command injection
def run_command(cmd):
    if 'command_injection' in ['xss', 'command_injection', 'idor', 'path_traversal', 'weak_crypto', 'auth_bypass', 'xxe']:
        os.system(f"ls {cmd}")
    else:
        os.system('ls')

# Deserialization vulnerability
def load_data(data):
    if 'deserialization' in ['xss', 'command_injection', 'idor', 'path_traversal', 'weak_crypto', 'auth_bypass', 'xxe']:
        return pickle.loads(data)
    return data

# Hardcoded credentials
if 'hardcoded_credentials' in ['xss', 'command_injection', 'idor', 'path_traversal', 'weak_crypto', 'auth_bypass', 'xxe']:
    API_KEY = 'hardcoded_api_key_12345'
    DB_PASSWORD = 'admin123'
    SECRET_TOKEN = 'super_secret_token'

users = {
    'admin': 'admin123',
    'user': 'password123',
    'guest': 'guestpass'
}
