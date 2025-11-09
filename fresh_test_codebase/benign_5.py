def safe_function_5():
    """A completely safe function."""
    return 5 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_5()
    print(f"Result: {result}")