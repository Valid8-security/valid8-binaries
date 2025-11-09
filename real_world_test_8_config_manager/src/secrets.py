# CWE-798: Hardcoded Secrets in separate file
API_KEY = 'hardcoded-api-key-abcdef123456'
DB_HOST = 'localhost'
DB_USER = 'admin'
DB_PASS = 'admin123'  # Hardcoded password

def get_database_config():
    return {
        'host': DB_HOST,
        'user': DB_USER,
        'password': DB_PASS
    }
