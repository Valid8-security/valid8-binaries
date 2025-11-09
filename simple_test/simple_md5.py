import hashlib
pwd = input()
hash = hashlib.md5(pwd.encode()).hexdigest()