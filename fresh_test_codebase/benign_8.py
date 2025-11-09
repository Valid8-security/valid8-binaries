def safe_function_8():
    """A completely safe function."""
    return 8 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_8()
    print(f"Result: {result}")