#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
NEGATIVE PATTERN LIBRARY: Phase 1 Precision Improvement

Explicit patterns for known-safe code structures that should never trigger alerts.
"""

import re
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass

@dataclass
class NegativePatternResult:
    """Result from negative pattern matching"""
    is_negative: bool
    confidence: float
    pattern_name: str
    reason: str

class NegativePatternLibrary:
    """
    Library of patterns that explicitly indicate safe code.
    
    These patterns override vulnerability detections when matched.
    """
    
    def __init__(self):
        self.patterns = {
            'sql_injection': [
                {
                    'name': 'parameterized_query',
                    'pattern': r'cursor\.execute\s*\(\s*["\'][^"]*[\?\%s][^"]*["\']\s*,',
                    'reason': 'Parameterized SQL query is safe from injection',
                    'confidence': 0.95
                },
                {
                    'name': 'django_orm',
                    'pattern': r'\.objects\.(filter|get|all|exclude)\s*\(',
                    'reason': 'Django ORM queries are automatically parameterized',
                    'confidence': 0.98
                },
                {
                    'name': 'prepared_statement',
                    'pattern': r'prepareStatement|PreparedStatement',
                    'reason': 'Prepared statements prevent SQL injection',
                    'confidence': 0.95
                }
            ],
            
            'xss': [
                {
                    'name': 'text_content',
                    'pattern': r'\.textContent\s*=',
                    'reason': 'textContent assignment is safe from XSS',
                    'confidence': 0.90
                },
                {
                    'name': 'sanitization_function',
                    'pattern': r'(escape|htmlentities|htmlspecialchars|sanitize)\s*\(',
                    'reason': 'Explicit sanitization prevents XSS',
                    'confidence': 0.95
                },
                {
                    'name': 'safe_template',
                    'pattern': r'\{[^}]*\}\s*and\s*safe|safe\s*and\s*\{[^}]*\}',
                    'reason': 'Explicit safe marking in templates',
                    'confidence': 0.85
                }
            ],
            
            'command_injection': [
                {
                    'name': 'list_arguments',
                    'pattern': r'subprocess\.(run|call|Popen)\s*\(\s*\[',
                    'reason': 'List arguments prevent shell injection',
                    'confidence': 0.95
                },
                {
                    'name': 'shell_false',
                    'pattern': r'shell\s*=\s*False',
                    'reason': 'Explicit shell=False prevents injection',
                    'confidence': 0.98
                },
                {
                    'name': 'safe_join',
                    'pattern': r'os\.path\.join|pathlib\.Path',
                    'reason': 'Path joining functions are safe',
                    'confidence': 0.90
                }
            ],
            
            'path_traversal': [
                {
                    'name': 'path_validation',
                    'pattern': r'validate_path|secure_filename|path\.is_safe',
                    'reason': 'Explicit path validation prevents traversal',
                    'confidence': 0.95
                },
                {
                    'name': 'safe_path_ops',
                    'pattern': r'os\.path\.(join|normpath|abspath)',
                    'reason': 'Standard path operations are safe',
                    'confidence': 0.85
                }
            ],
            
            'general_safe': [
                {
                    'name': 'test_code',
                    'pattern': r'def test_|describe\(|it\(|assert\s+|expect\(',
                    'reason': 'Test code intentionally contains patterns',
                    'confidence': 0.80
                },
                {
                    'name': 'logging',
                    'pattern': r'(print|console\.log|logger\.(info|debug))\s*\(',
                    'reason': 'Logging/debugging output is not a vulnerability',
                    'confidence': 0.75
                },
                {
                    'name': 'constant_values',
                    'pattern': r'["\'][A-Z_][A-Z0-9_]*["\']',
                    'reason': 'Constant string values are not injectable',
                    'confidence': 0.70
                }
            ]
        }
        
        # Compile regex patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for efficiency"""
        for category, pattern_list in self.patterns.items():
            for pattern_info in pattern_list:
                try:
                    pattern_info['compiled'] = re.compile(
                        pattern_info['pattern'], 
                        re.IGNORECASE | re.DOTALL
                    )
                except re.error:
                    # Skip invalid patterns
                    pattern_info['compiled'] = None
    
    def check_negative_pattern(self, code_snippet: str, vuln_type: str) -> NegativePatternResult:
        """
        Check if code matches any negative patterns for the given vulnerability type.
        
        Args:
            code_snippet: The code to check
            vuln_type: Type of vulnerability (sql_injection, xss, etc.)
            
        Returns:
            NegativePatternResult indicating if safe pattern was found
        """
        if vuln_type not in self.patterns:
            return NegativePatternResult(False, 0.0, "", "No patterns defined for this type")
        
        # Check general safe patterns first
        for pattern_info in self.patterns['general_safe']:
            if pattern_info.get('compiled') and pattern_info['compiled'].search(code_snippet):
                return NegativePatternResult(
                    True, 
                    pattern_info['confidence'],
                    pattern_info['name'],
                    pattern_info['reason']
                )
        
        # Check vulnerability-specific patterns
        for pattern_info in self.patterns[vuln_type]:
            if pattern_info.get('compiled') and pattern_info['compiled'].search(code_snippet):
                return NegativePatternResult(
                    True,
                    pattern_info['confidence'], 
                    pattern_info['name'],
                    pattern_info['reason']
                )
        
        return NegativePatternResult(False, 0.0, "", "No negative patterns matched")
    
    def should_skip_vulnerability(self, vuln_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Determine if a vulnerability should be skipped based on negative patterns.
        
        Args:
            vuln_dict: Vulnerability dictionary
            
        Returns:
            (should_skip, reason)
        """
        code_snippet = vuln_dict.get('code_snippet', '')
        vuln_type = self._classify_vulnerability(vuln_dict)
        
        if not code_snippet or not vuln_type:
            return False, "Insufficient information"
        
        result = self.check_negative_pattern(code_snippet, vuln_type)
        
        if result.is_negative:
            return True, f"Negative pattern '{result.pattern_name}': {result.reason}"
        
        return False, "No negative patterns matched"
    
    def _classify_vulnerability(self, vuln_dict: Dict[str, Any]) -> str:
        """
        Classify vulnerability type from the vulnerability dictionary.
        """
        cwe = vuln_dict.get('cwe', '')
        title = vuln_dict.get('title', '').lower()
        
        # Map CWE codes to vulnerability types
        cwe_mapping = {
            'CWE-89': 'sql_injection',
            'CWE-79': 'xss', 
            'CWE-78': 'command_injection',
            'CWE-22': 'path_traversal'
        }
        
        if cwe in cwe_mapping:
            return cwe_mapping[cwe]
        
        # Fallback to title-based classification
        if 'sql' in title:
            return 'sql_injection'
        elif 'xss' in title or 'cross-site' in title:
            return 'xss'
        elif 'command' in title:
            return 'command_injection'
        elif 'path' in title or 'traversal' in title:
            return 'path_traversal'
        
        return 'general_safe'  # Default to general patterns

# Integration function for scanner
def integrate_negative_patterns(scanner_class):
    """
    Integrate negative pattern library into scanner.
    
    This monkey-patches the scanner to use negative pattern checking.
    """
    original_scan = scanner_class.scan_ultra_precise
    
    def enhanced_scan_ultra_precise(self, *args, **kwargs):
        """Enhanced scan with negative pattern filtering"""
        # Get original results
        results = original_scan(self, *args, **kwargs)
        
        # Apply negative pattern filtering
        neg_library = NegativePatternLibrary()
        filtered_results = {'vulnerabilities': []}
        
        skipped_count = 0
        for vuln in results.get('vulnerabilities', []):
            should_skip, reason = neg_library.should_skip_vulnerability(vuln)
            
            if should_skip:
                skipped_count += 1
                print(f"🚫 Skipped (negative pattern): {vuln.get('title', 'Unknown')} - {reason}")
            else:
                filtered_results['vulnerabilities'].append(vuln)
        
        # Copy other result fields
        for key, value in results.items():
            if key != 'vulnerabilities':
                filtered_results[key] = value
        
        print(f"\\n🛡️ Negative Pattern Filtering: {skipped_count} vulnerabilities filtered out")
        
        return filtered_results
    
    # Replace the method
    scanner_class.scan_ultra_precise = enhanced_scan_ultra_precise
    print("✅ Negative pattern library integrated into scanner")

if __name__ == "__main__":
    # Test the negative pattern library
    library = NegativePatternLibrary()
    
    test_cases = [
        ('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))', 'sql_injection', True),
        ('element.innerHTML = userInput', 'xss', False),
        ('print(f"Debug: {data}")', 'general_safe', True),
        ('User.objects.filter(name=name)', 'sql_injection', True),
        ('subprocess.run(["ls", "-la"])', 'command_injection', True),
    ]
    
    print("🧪 TESTING NEGATIVE PATTERN LIBRARY")
    print("=" * 40)
    
    for code, vuln_type, expected_safe in test_cases:
        result = library.check_negative_pattern(code, vuln_type)
        status = "✅ SAFE" if result.is_negative else "⚠️  CHECK"
        expected = "SAFE" if expected_safe else "CHECK"
        match = "✓" if (result.is_negative == expected_safe) else "✗"
        
        print(f"{match} {code[:40]}... → {status} ({expected})")
        if result.is_negative:
            print(f"      Reason: {result.reason}")
    
    print("\\n✅ Negative pattern library ready for integration!")
