
# VULNERABLE: Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
SECRET = "my-secret-key"

def connect_db():
    # VULNERABLE: Hardcoded password
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        database="mydb",
        user="admin",
        password="admin123"
    )
    return conn
