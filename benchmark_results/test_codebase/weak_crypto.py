
import hashlib
import md5

def hash_password(password):
    # VULNERABLE: Weak hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_weak(password):
    # VULNERABLE: Weak hash (SHA1)
    return hashlib.sha1(password.encode()).hexdigest()

def hash_password_secure(password):
    # SECURE: Strong hash
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
