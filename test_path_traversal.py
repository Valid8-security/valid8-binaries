from flask import request
filename = request.args.get('file')
with open(f'/var/www/files/{filename}', 'r') as f:
    content = f.read()