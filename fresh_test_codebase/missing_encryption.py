# CWE-311: Missing Encryption of Sensitive Data
user_credentials = {
    'username': 'admin',
    'password': 'secret123'  # Stored in plain text
}
def get_credentials():
    return user_credentials