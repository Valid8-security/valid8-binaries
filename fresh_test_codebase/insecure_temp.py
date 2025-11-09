import tempfile
def create_temp_file():
    # CWE-377: Insecure Temporary File
    with open('/tmp/myapp_temp', 'w') as f:
        f.write('sensitive data')
    return '/tmp/myapp_temp' 