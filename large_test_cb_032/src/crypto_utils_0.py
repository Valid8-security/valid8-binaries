import os
import json
from flask import Flask, request

app = Flask(__name__)

def path_traversal_function_0():
    # PATH_TRAVERSAL VULNERABILITY
    shutil.copy(src, f"{dst}")
    return "done"

def path_traversal_function_1():
    # PATH_TRAVERSAL VULNERABILITY
    with open(f"/tmp/{filename}", "r") as f:
    return "done"

def path_traversal_function_2():
    # PATH_TRAVERSAL VULNERABILITY
    os.listdir(path)
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
