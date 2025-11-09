filename = input()
with open(f'/tmp/{filename}') as f:
    content = f.read()