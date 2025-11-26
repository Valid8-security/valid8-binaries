#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Test script to verify Ollama connection and model
"""

import sys
from parry.llm import LLMClient


def main():
    print("Testing Ollama connection...")
    print("-" * 50)
    
    try:
        # Initialize client
        client = LLMClient()
        print("✓ Connected to Ollama")
        
        # List models
        print("\nAvailable models:")
        models = client.list_models()
        for model in models:
            print(f"  - {model['name']}")
        
        # Test generation
        print("\nTesting code generation...")
        prompt = """Fix this SQL injection vulnerability:
        
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

Provide only the fixed code."""
        
        response = client.generate(prompt)
        print("\nLLM Response:")
        print(response)
        
        print("\n✓ All tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nMake sure Ollama is running:")
        print("  ollama serve")
        print("\nAnd that you have a model installed:")
        print("  ollama pull codellama:7b-instruct")
        return 1


if __name__ == "__main__":
    sys.exit(main())


