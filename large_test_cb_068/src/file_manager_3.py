import os
import json
from flask import Flask, request

app = Flask(__name__)

def path_traversal_function_0():
    # PATH_TRAVERSAL VULNERABILITY
    os.listdir(path)
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
