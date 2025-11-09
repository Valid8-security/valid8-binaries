from flask import Flask, request
app = Flask(__name__)
@app.route('/greet')
def greet_user():
    # CWE-79: XSS
    name = request.args.get('name', 'Guest')
    return f'<h1>Hello {name}</h1>'  # Direct injection without escaping