def safe_function_2():
    """A completely safe function."""
    return 2 * 2

class SafeClass:
    def method(self):
        return "safe"

if __name__ == "__main__":
    result = safe_function_2()
    print(f"Result: {result}")