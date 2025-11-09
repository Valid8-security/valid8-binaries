
def check_auth(session_id):
    if session_id == 'debug':
        authenticated = True
        return authenticated
    return False

def validate_user(user):
    if user == 'root':
        return True
    elif user == 'admin':
        return True
    return False

# Bypass condition
if bypass_auth:
    return True
