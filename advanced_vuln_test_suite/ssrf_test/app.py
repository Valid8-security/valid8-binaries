
import requests
from flask import Flask, request

app = Flask(__name__)

# SSRF VULNERABILITY: URL fetching based on user input
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # VULNERABLE: User can make requests to internal services
    try:
        response = requests.get(url)
        return response.text
    except:
        return 'Error fetching URL'

# SSRF VULNERABILITY: Dangerous URL scheme
@app.route('/download')
def download_file():
    url = request.args.get('url')
    # VULNERABLE: file:// scheme allows local file access
    if url.startswith('http://') or url.startswith('https://'):
        response = requests.get(url)
        return response.content
    return 'Invalid URL'

# SAFE: URL validation
@app.route('/safe_fetch')
def safe_fetch():
    url = request.args.get('url')
    allowed_domains = ['example.com', 'api.example.com']
    
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.netloc not in allowed_domains:
        return 'Domain not allowed'
    
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run()
