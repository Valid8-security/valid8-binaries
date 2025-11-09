
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'secret'

# CSRF VULNERABILITY: State-changing operation without CSRF protection
@app.route('/change_password', methods=['POST'])
def change_password():
    new_password = request.form['password']
    user_id = session.get('user_id')
    # VULNERABLE: No CSRF token validation
    # Attacker can trick user into changing password
    update_password(user_id, new_password)
    return 'Password changed'

# CSRF VULNERABILITY: Delete account without protection
@app.route('/delete_account', methods=['POST'])
def delete_account():
    user_id = session.get('user_id')
    # VULNERABLE: State-changing without CSRF protection
    delete_user(user_id)
    return 'Account deleted'

# SAFE: CSRF protected operation
@app.route('/safe_change_password', methods=['POST'])
def safe_change_password():
    # SAFE: Check CSRF token
    token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    
    if not token or token != session_token:
        return 'CSRF token invalid', 403
    
    new_password = request.form['password']
    user_id = session.get('user_id')
    update_password(user_id, new_password)
    return 'Password safely changed'

# SAFE: Using Flask-WTF CSRF protection (conceptual)
@app.route('/wtf_protected', methods=['POST'])
def wtf_protected():
    # In real Flask-WTF, this would be @csrf.exempt or automatic protection
    # This is conceptual
    return 'CSRF protected by framework'

def update_password(user_id, password):
    # Mock function
    pass

def delete_user(user_id):
    # Mock function
    pass

if __name__ == '__main__':
    app.run()
