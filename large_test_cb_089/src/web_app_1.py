import os
import json
from flask import Flask, request

app = Flask(__name__)

def file_upload_function_0():
    # FILE_UPLOAD VULNERABILITY
    with open(filename, "wb") as f:
    return "done"

def file_upload_function_1():
    # FILE_UPLOAD VULNERABILITY
    with open(filename, "wb") as f:
    return "done"

def file_upload_function_2():
    # FILE_UPLOAD VULNERABILITY
    with open(filename, "wb") as f:
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
