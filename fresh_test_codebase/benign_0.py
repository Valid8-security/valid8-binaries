def safe_function_0():
    """A completely safe function."""
    return 0 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_0()
    print(f"Result: {result}")