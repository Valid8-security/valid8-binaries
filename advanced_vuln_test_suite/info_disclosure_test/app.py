
from flask import Flask, request
import traceback
import os

app = Flask(__name__)

# INFORMATION DISCLOSURE: Sensitive data in response
@app.route('/user_info/<user_id>')
def user_info(user_id):
    user_data = {
        'id': user_id,
        'name': 'John Doe',
        'password': 'hashed_password_123',  # VULNERABLE: Password hash exposed
        'ssn': '123-45-6789',               # VULNERABLE: SSN exposed
        'api_key': 'sk-1234567890abcdef',   # VULNERABLE: API key exposed
        'credit_card': '4111111111111111'   # VULNERABLE: Credit card exposed
    }
    return user_data

# INFORMATION DISCLOSURE: Detailed error messages
@app.route('/process')
def process():
    try:
        # Simulate an error that reveals internal information
        result = 1 / 0  # This will cause ZeroDivisionError
        return {'result': result}
    except Exception as e:
        # VULNERABLE: Detailed error information exposed
        return {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'system_info': os.uname(),  # VULNERABLE: System information
            'working_dir': os.getcwd()  # VULNERABLE: Working directory
        }

# INFORMATION DISCLOSURE: Debug information in production
@app.route('/debug_info')
def debug_info():
    if app.debug:
        # VULNERABLE: Debug information exposed
        return {
            'config': str(app.config),
            'session': dict(session),
            'environment': dict(os.environ)  # VULNERABLE: All environment variables
        }
    return {'debug': 'disabled'}

# SAFE: Sanitized error response
@app.route('/safe_process')
def safe_process():
    try:
        result = 1 / 0
        return {'result': result}
    except Exception as e:
        # SAFE: Generic error message without details
        return {
            'error': 'An error occurred while processing your request',
            'code': 'PROCESSING_ERROR'
        }, 500

# SAFE: Masked sensitive data
@app.route('/safe_user_info/<user_id>')
def safe_user_info(user_id):
    user_data = {
        'id': user_id,
        'name': 'John Doe',
        'password': '***masked***',        # SAFE: Masked
        'ssn': '***-**-****',             # SAFE: Masked
        'api_key': 'sk-****' + '****'*4,  # SAFE: Partially masked
        'credit_card': '****-****-****-' + '1111'  # SAFE: Masked except last 4
    }
    return user_data

if __name__ == '__main__':
    app.run(debug=True)  # VULNERABLE: Debug mode in production
