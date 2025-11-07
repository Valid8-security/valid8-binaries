from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # CWE-79: Cross-Site Scripting
    return f'<h1>Search results for: {query}</h1>'