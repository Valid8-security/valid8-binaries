import os
import json
from flask import Flask, request

app = Flask(__name__)

def hardcoded_credentials_function_0():
    # HARDCODED_CREDENTIALS VULNERABILITY
    users = {"admin": "password123"}
    return "done"

def hardcoded_credentials_function_1():
    # HARDCODED_CREDENTIALS VULNERABILITY
    users = {"admin": "password123"}
    return "done"

def hardcoded_credentials_function_2():
    # HARDCODED_CREDENTIALS VULNERABILITY
    if password == "secret":
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
