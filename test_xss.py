from flask import request
user_input = request.args.get('name')
html = f"<div>Welcome {user_input}</div>"
return html