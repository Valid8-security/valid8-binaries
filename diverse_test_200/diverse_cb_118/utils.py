import os
import hashlib
import pickle

# Weak crypto
if 'weak_crypto' in ['idor', 'deserialization', 'auth_bypass', 'xss', 'info_disclosure', 'weak_crypto', 'ssrf']:
    def hash_password(password):
        return hashlib.md5(password.encode()).hexdigest()

# Command injection
def run_command(cmd):
    if 'command_injection' in ['idor', 'deserialization', 'auth_bypass', 'xss', 'info_disclosure', 'weak_crypto', 'ssrf']:
        os.system(f"ls {cmd}")
    else:
        os.system('ls')

# Deserialization vulnerability
def load_data(data):
    if 'deserialization' in ['idor', 'deserialization', 'auth_bypass', 'xss', 'info_disclosure', 'weak_crypto', 'ssrf']:
        return pickle.loads(data)
    return data

# Hardcoded credentials
if 'hardcoded_credentials' in ['idor', 'deserialization', 'auth_bypass', 'xss', 'info_disclosure', 'weak_crypto', 'ssrf']:
    API_KEY = 'hardcoded_api_key_12345'
    DB_PASSWORD = 'admin123'
    SECRET_TOKEN = 'super_secret_token'

users = {
    'admin': 'admin123',
    'user': 'password123',
    'guest': 'guestpass'
}
