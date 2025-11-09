from flask import Flask, request, jsonify
import jwt
import pickle
import subprocess

app = Flask(__name__)

@app.route('/api/v1/process', methods=['POST'])
def process_data():
    # CWE-502: Unsafe Deserialization
    data = request.get_data()
    obj = pickle.loads(data)  # Deserialization vulnerability
    return jsonify({'result': str(obj)})

@app.route('/api/v1/execute')
def execute_code():
    # CWE-95: Code Injection
    code = request.args.get('code')
    result = eval(code)  # Code injection
    return jsonify({'result': result})

@app.route('/api/v1/token')
def generate_token():
    # CWE-798: Hardcoded Secret
    secret = 'my-secret-key-12345'  # Hardcoded
    token = jwt.encode({'user': 'admin'}, secret, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/v1/run')
def run_service():
    # CWE-78: Command Injection
    service = request.args.get('service')
    subprocess.call([service])  # Command injection
    return 'Service started'

if __name__ == '__main__':
    app.run()
