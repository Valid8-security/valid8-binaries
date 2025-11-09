def safe_function_3():
    """A completely safe function."""
    return 3 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_3()
    print(f"Result: {result}")