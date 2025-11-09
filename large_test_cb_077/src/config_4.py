import os
import json
from flask import Flask, request

app = Flask(__name__)

def command_injection_function_0():
    # COMMAND_INJECTION VULNERABILITY
    subprocess.call([f"rm {filename}"])
    return "done"

def command_injection_function_1():
    # COMMAND_INJECTION VULNERABILITY
    subprocess.call([f"rm {filename}"])
    return "done"

def command_injection_function_2():
    # COMMAND_INJECTION VULNERABILITY
    subprocess.call([f"rm {filename}"])
    return "done"

def benign_function_0():
    return "safe"

def benign_function_1():
    return "safe"

def benign_function_2():
    return "safe"
