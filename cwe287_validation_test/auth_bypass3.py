
def api_auth(api_key):
    if api_key == 'hardcoded_key':
        return True
    return False

def session_check(session):
    if session == 'valid_session_token':
        return True
    return False

# OR-based weak auth
if user == 'admin' or password == 'password':
    return True
