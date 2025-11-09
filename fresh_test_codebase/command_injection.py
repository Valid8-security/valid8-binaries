import subprocess
def execute_command(user_cmd):
    # CWE-78: Command Injection  
    result = subprocess.run(f'ls {user_cmd}', shell=True, capture_output=True)
    return result.stdout.decode()