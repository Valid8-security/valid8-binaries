def safe_function_6():
    """A completely safe function."""
    return 6 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_6()
    print(f"Result: {result}")