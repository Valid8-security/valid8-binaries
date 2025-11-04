
import os
import subprocess

def ping_host(hostname):
    # VULNERABLE: Command Injection
    os.system("ping -c 1 " + hostname)

def run_command(cmd):
    # VULNERABLE: Command Injection
    subprocess.call("ls " + cmd, shell=True)

def safe_ping(hostname):
    # SECURE: No shell, parameterized
    subprocess.run(["ping", "-c", "1", hostname])
