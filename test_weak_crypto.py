import hashlib
password = 'secret'
hash_value = hashlib.md5(password.encode()).hexdigest()