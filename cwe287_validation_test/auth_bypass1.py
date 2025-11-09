
def authenticate(user_input):
    if user_input == 'admin':
        return True
    return False

def login(token):
    if token == 'secret123':
        return True
    return False

@app.route('/admin')
def admin_panel():
    # No authentication check!
    return 'Admin access granted'
