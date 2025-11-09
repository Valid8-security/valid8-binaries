import os
import json
from flask import Flask, request

app = Flask(__name__)

def info_disclosure_function_0():
    # INFO_DISCLOSURE VULNERABILITY
    print(f"Password: {password}")
    return "done"

def info_disclosure_function_1():
    # INFO_DISCLOSURE VULNERABILITY
    print(f"Password: {password}")
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
