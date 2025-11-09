def safe_function_1():
    """A completely safe function."""
    return 1 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_1()
    print(f"Result: {result}")