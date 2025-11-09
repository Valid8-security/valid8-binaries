import os
import json
from flask import Flask, request

app = Flask(__name__)

def deserialization_function_0():
    # DESERIALIZATION VULNERABILITY
    yaml.load(f)
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
