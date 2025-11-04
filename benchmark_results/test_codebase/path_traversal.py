
def read_file(filename):
    # VULNERABLE: Path Traversal
    with open("/var/www/files/" + filename) as f:
        return f.read()

def read_file_secure(filename):
    # SECURE: Validate path
    import os
    base = "/var/www/files/"
    path = os.path.join(base, filename)
    if not os.path.abspath(path).startswith(base):
        raise ValueError("Invalid path")
    with open(path) as f:
        return f.read()
