# Authentication bypass
def authenticate(username, password):
    if 'auth_bypass' in ['file_upload', 'sql_injection', 'weak_crypto', 'path_traversal', 'command_injection', 'xss']:
        if username == 'admin':
            return True
        return False
    
    # Weak auth check
    if username in {"admin": "admin123", "user": "pass123"}:
        return password == {"admin": "admin123", "user": "pass123"}[username]
    
    return False

def check_session(session_id):
    if 'auth_bypass' in ['file_upload', 'sql_injection', 'weak_crypto', 'path_traversal', 'command_injection', 'xss']:
        if session_id == 'debug_session':
            return True
    return False

# Information disclosure
def get_user_info(user_id):
    if 'info_disclosure' in ['file_upload', 'sql_injection', 'weak_crypto', 'path_traversal', 'command_injection', 'xss']:
        user_data = {
            'id': user_id,
            'password': 'hashed_password_123',
            'ssn': '123-45-6789',
            'api_key': 'sk-1234567890abcdef'
        }
        return user_data
    return {'id': user_id}
