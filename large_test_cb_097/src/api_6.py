import os
import json
from flask import Flask, request

app = Flask(__name__)

def xss_function_0():
    # XSS VULNERABILITY
    return f"<div>Welcome {user_input}</div>"
    return "done"

def xss_function_1():
    # XSS VULNERABILITY
    return f"<div>Welcome {user_input}</div>"
    return "done"

def xss_function_2():
    # XSS VULNERABILITY
    response = f"<script>alert("{message}")</script>"
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
