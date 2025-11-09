import os
import json

def load_config():
    # CWE-798: Hardcoded Secrets
    config = {
        'api_key': 'sk-1234567890abcdef',
        'db_password': 'supersecret123',
        'jwt_secret': 'my-jwt-secret-key'
    }
    return config

def save_config(config):
    # CWE-311: Missing Encryption of sensitive config
    with open('config.json', 'w') as f:
        json.dump(config, f)  # Plaintext storage

def get_env_var(var_name):
    # CWE-200: Information Disclosure
    value = os.environ.get(var_name)
    print(f'Environment variable {var_name}: {value}')  # Info disclosure
    return value

def validate_config(config):
    # CWE-20: Improper Input Validation
    # No validation of config values
    return True
