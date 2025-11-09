import os
import shutil
import tempfile

def read_file(filepath):
    # CWE-22: Path Traversal
    with open(filepath, 'r') as f:  # No path validation
        return f.read()

def copy_file(src, dst):
    # CWE-22: Path Traversal in copy operations
    shutil.copy(src, dst)  # No validation

def create_temp_file(content):
    # CWE-377: Insecure Temporary File
    with open('/tmp/temp_file.txt', 'w') as f:  # Hardcoded temp path
        f.write(content)
    return '/tmp/temp_file.txt'

def execute_script(script_path):
    # CWE-78: Command Injection via file execution
    os.system(f'python {script_path}')  # Command injection

def list_directory(path):
    # CWE-22: Directory Traversal
    return os.listdir(path)  # No validation

def save_uploaded_file(upload_data, filename):
    # CWE-434: Unrestricted File Upload
    with open(filename, 'wb') as f:  # No validation of filename
        f.write(upload_data)
