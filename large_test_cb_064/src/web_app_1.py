import os
import json
from flask import Flask, request

app = Flask(__name__)

def weak_crypto_function_0():
    # WEAK_CRYPTO VULNERABILITY
    hashlib.md5(password.encode()).hexdigest()
    return "done"

def weak_crypto_function_1():
    # WEAK_CRYPTO VULNERABILITY
    hashlib.md5(password.encode()).hexdigest()
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
