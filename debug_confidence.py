#!/usr/bin/env python3
"""
Debug confidence scoring functionality
"""

import sys
sys.path.insert(0, '.')

from parry.ai_detector import AIDetector

def test_confidence_scoring():
    detector = AIDetector()

    # Test cases with different confidence levels
    test_cases = [
        {
            'name': 'High confidence - eval usage',
            'code': 'user_input = get_data()\neval(user_input)',
            'expected': 'high'
        },
        {
            'name': 'High confidence - SQL injection',
            'code': 'query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)',
            'expected': 'high'
        },
        {
            'name': 'Medium confidence - innerHTML',
            'code': 'element.innerHTML = userData',
            'expected': 'medium'
        },
        {
            'name': 'Low confidence - normal code',
            'code': 'def calculate(x, y):\n    return x + y',
            'expected': 'low'
        }
    ]

    print("🔍 DEBUGGING CONFIDENCE SCORING")
    print("=" * 50)

    for test_case in test_cases:
        confidence = detector.score_pattern_confidence(test_case['code'], 'test.py', 'python')
        should_skip = detector.should_skip_ai_analysis(test_case['code'], 'test.py', 'python')

        print(f"\nTest: {test_case['name']}")
        print(f"Code: {test_case['code'][:50]}...")
        print(".3f")
        print(f"Should skip AI: {should_skip}")
        print(f"Expected: {test_case['expected']}")

if __name__ == "__main__":
    test_confidence_scoring()
