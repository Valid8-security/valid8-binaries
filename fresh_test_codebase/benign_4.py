def safe_function_4():
    """A completely safe function."""
    return 4 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_4()
    print(f"Result: {result}")