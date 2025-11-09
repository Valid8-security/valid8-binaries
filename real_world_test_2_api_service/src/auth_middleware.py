def authenticate_token(token):
    # CWE-287: Improper Authentication - weak check
    if token == 'admin-token':
        return True
    return False

def authorize_admin(user_id):
    # CWE-285: Improper Authorization
    # No proper authorization check
    return True
