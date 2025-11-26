#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
CONTEXT-AWARE PRE-FILTERING: Phase 1 Foundation Fix
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

@dataclass
class PrefilterResult:
    """Result from context-aware pre-filtering"""
    should_skip: bool
    confidence: float
    reason: str
    safe_patterns_found: List[str]

class ContextAwarePrefilter:
    """
    Pre-filters vulnerabilities before pattern matching to reduce false positives.
    """
    
    def __init__(self):
        # Safe code patterns that should never be flagged
        self.safe_patterns = {
            'parameterized_sql': {
                'patterns': [
                    r'cursor\.execute\s*\(\s*["\'][^"]*[\?\%s][^"]*["\']\s*,',  # ? placeholders
                    r'cursor\.execute\s*\(\s*["\'][^"]*\%\([^)]+\)[^"]*["\']\s*,',  # %() placeholders
                    r'prepared.*statement',
                ],
                'reason': 'Parameterized SQL queries are safe from injection',
                'confidence': 0.95
            },
            
            'input_sanitization': {
                'patterns': [
                    r'sanitize\s*\(',
                    r'escape\s*\(',
                    r'htmlentities\s*\(',
                    r'htmlspecialchars\s*\(',
                    r'bleach\.clean\s*\(',
                ],
                'reason': 'Input sanitization functions prevent injection attacks',
                'confidence': 0.90
            },
            
            'framework_orm': {
                'patterns': [
                    r'objects\.(filter|get|all|exclude)\s*\(',
                    r'Model\.objects\.',
                ],
                'reason': 'ORM queries are parameterized by design',
                'confidence': 0.95
            },
            
            'test_code': {
                'patterns': [
                    r'def test_',
                    r'describe\s*\(',
                    r'it\s*\(',
                    r'assert\s+',
                ],
                'reason': 'Test code intentionally contains vulnerability patterns',
                'confidence': 0.80
            },
            
            'logging_debugging': {
                'patterns': [
                    r'print\s*\(',
                    r'console\.log\s*\(',
                    r'logger\.(info|debug|warning)\s*\(',
                ],
                'reason': 'Logging and debugging output is not a vulnerability',
                'confidence': 0.75
            }
        }
        
        # Compile regex patterns for efficiency
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        for category, config in self.safe_patterns.items():
            compiled_patterns = []
            for pattern in config['patterns']:
                try:
                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
                except re.error:
                    continue
            config['compiled_patterns'] = compiled_patterns
    
    def prefilter_vulnerability(self, vuln_dict: Dict[str, Any]) -> PrefilterResult:
        """
        Pre-filter a potential vulnerability before pattern matching.
        """
        code_snippet = vuln_dict.get('code_snippet', '')
        if not code_snippet:
            return PrefilterResult(False, 0.0, "No code snippet available", [])
        
        safe_patterns_found = []
        max_confidence = 0.0
        best_reason = "No safe patterns detected"
        
        # Check each safe pattern category
        for category, config in self.safe_patterns.items():
            confidence = config['confidence']
            reason = config['reason']
            
            # Check if any pattern matches
            for pattern in config['compiled_patterns']:
                if pattern.search(code_snippet):
                    safe_patterns_found.append(category)
                    if confidence > max_confidence:
                        max_confidence = confidence
                        best_reason = reason
                    break
        
        # Decision: skip if we found strong evidence of safety
        should_skip = max_confidence >= 0.8
        
        return PrefilterResult(
            should_skip=should_skip,
            confidence=max_confidence,
            reason=best_reason,
            safe_patterns_found=safe_patterns_found
        )

def main():
    """Demonstrate context-aware pre-filtering"""
    
    print("🛡️  CONTEXT-AWARE PRE-FILTERING DEMONSTRATION")
    print("=" * 50)
    
    # Create prefilter
    prefilter = ContextAwarePrefilter()
    
    # Test cases
    test_cases = [
        {
            'code_snippet': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            'title': 'SQL Query',
            'expected': 'SKIP - Safe parameterized query'
        },
        {
            'code_snippet': 'element.innerHTML = user_input',
            'title': 'XSS Attempt',
            'expected': 'PROCESS - Dangerous pattern'
        },
        {
            'code_snippet': 'print(f"Debug: {user_data}")',
            'title': 'Debug Output',
            'expected': 'SKIP - Logging/debugging'
        },
        {
            'code_snippet': 'User.objects.filter(name__icontains=search_term)',
            'title': 'ORM Query',
            'expected': 'SKIP - Safe ORM usage'
        }
    ]
    
    print("\\n🧪 TESTING PRE-FILTERING:")
    print("-" * 30)
    
    total_skipped = 0
    for i, test_case in enumerate(test_cases, 1):
        result = prefilter.prefilter_vulnerability(test_case)
        
        status = "🚫 SKIP" if result.should_skip else "✅ PROCESS"
        print(f"{i}. {test_case['title']}")
        print(f"   Code: {test_case['code_snippet'][:50]}...")
        print(f"   Result: {status} ({result.confidence:.1f})")
        print(f"   Reason: {result.reason}")
        
        if result.should_skip:
            total_skipped += 1
        
        print()
    
    skip_rate = total_skipped / len(test_cases) * 100
    print(f"📊 SUMMARY:")
    print(f"   Total test cases: {len(test_cases)}")
    print(f"   Would skip: {total_skipped}")
    print(f"   Skip rate: {skip_rate:.1f}%")
    print("\\n🎯 This demonstrates false positive reduction potential")

if __name__ == "__main__":
    main()
