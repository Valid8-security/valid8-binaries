def execute_user_code(code):
    # CWE-95: Code Injection
    exec(code)  # Dangerous