import subprocess
user_cmd = input()
subprocess.run(f'ls {user_cmd}', shell=True)