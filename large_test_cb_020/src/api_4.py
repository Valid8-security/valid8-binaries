import os
import json
from flask import Flask, request

app = Flask(__name__)

def missing_auth_function_0():
    # MISSING_AUTH VULNERABILITY
    if token != "valid-token":
    return "done"

def missing_auth_function_1():
    # MISSING_AUTH VULNERABILITY
    @app.route("/admin")
    return "done"

def missing_auth_function_2():
    # MISSING_AUTH VULNERABILITY
    @app.route("/admin")
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
