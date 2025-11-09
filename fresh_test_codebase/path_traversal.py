def read_file(filename):
    # CWE-22: Path Traversal
    with open(f'/tmp/{filename}', 'r') as f:
        return f.read()