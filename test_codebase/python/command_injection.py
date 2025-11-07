import subprocess
import os

def run_command(user_cmd):
    # CWE-78: Command Injection
    os.system(f"ls -la {user_cmd}")