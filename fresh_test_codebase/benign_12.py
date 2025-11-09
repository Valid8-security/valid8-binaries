def safe_function_12():
    """A completely safe function."""
    return 12 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_12()
    print(f"Result: {result}")