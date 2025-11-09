def safe_function_10():
    """A completely safe function."""
    return 10 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_10()
    print(f"Result: {result}")