# CWE-287: Improper Authentication
def authenticate(username, password):
    # No proper authentication checks
    if username == 'admin' and password == 'password':
        return True
    return False