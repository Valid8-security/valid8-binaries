"""
Universal CWE detectors that apply to all or most languages.

These detectors implement vulnerability patterns that are language-agnostic
or can be adapted across multiple languages with minimal changes.
"""

import re
from typing import List
from .base import Vulnerability


class UniversalDetectors:
    """Mixin class providing universal vulnerability detection methods."""
    
    def detect_improper_input_validation(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-20: Improper Input Validation."""
        patterns = [
            # Direct use of user input without validation
            (r'(request|req|input|user_input|params|args)\[.*\].*(?!validate|sanitize|check|verify)', 'Direct use of user input'),
            # Missing validation before critical operations
            (r'(execute|eval|exec|system|open|read|write)\s*\([^)]*?(request|input|params)', 'Critical operation with unvalidated input'),
            # No length checks before operations
            (r'(malloc|alloc|buffer|array)\s*\([^)]*?(request|input)', 'Memory operation without size validation'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-20',
                        severity='high',
                        title='Improper Input Validation',
                        description=f'{desc}. Always validate and sanitize user input before use.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_information_exposure(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-200: Exposure of Sensitive Information."""
        patterns = [
            # Sensitive data in logs
            (r'(log|console|print|echo|write)\s*\([^)]*?(password|token|key|secret|credential)', 'Sensitive data in logs'),
            # Error messages with sensitive data
            (r'(error|exception|throw)\s*\([^)]*?(password|token|key|sql|query)', 'Sensitive data in error messages'),
            # Exposing internal paths
            (r'(error|exception)\s*\([^)]*?(__file__|__dir__|filepath|path)', 'Internal paths in error messages'),
            # Stack traces to user
            (r'(print|echo|write|send)\s*\([^)]*?(traceback|stacktrace|backtrace)', 'Stack trace exposure'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-200',
                        severity='medium',
                        title='Exposure of Sensitive Information',
                        description=f'{desc}. Avoid exposing sensitive data in logs or error messages.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_improper_authentication(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-287: Improper Authentication."""
        patterns = [
            # Weak authentication checks
            (r'if\s+.*(?:password|pwd|pass)\s*==\s*["\'][^"\']+["\']', 'Hard-coded password comparison'),
            # Authentication bypass
            (r'if\s+.*(?:auth|authenticated|logged_in)\s*==\s*(?:false|0|null)', 'Potential authentication bypass'),
            # Missing authentication
            (r'(?:route|endpoint|api|handler).*(?!@auth|@login_required|@require|authenticate)', 'Endpoint without authentication'),
            # Weak session checks
            (r'if\s+.*session\[.*\]\s*==\s*["\'][^"\']+["\']', 'Weak session validation'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-287',
                        severity='high',
                        title='Improper Authentication',
                        description=f'{desc}. Implement proper authentication mechanisms.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_csrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-352: Cross-Site Request Forgery."""
        patterns = [
            # POST without CSRF token
            (r'(?:@route|@post|\.post|POST).*(?!csrf|token|@csrf_protect)', 'POST endpoint without CSRF protection'),
            # Form without CSRF token
            (r'<form[^>]*method\s*=\s*["\']post["\'][^>]*(?!csrf)', 'Form without CSRF token'),
            # State-changing operation without CSRF
            (r'(?:update|delete|create|modify).*(?!csrf|token)', 'State-changing operation without CSRF protection'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if self._is_comment(line):
                continue
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-352',
                        severity='high',
                        title='Cross-Site Request Forgery (CSRF)',
                        description=f'{desc}. Implement CSRF tokens for state-changing operations.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_incorrect_permissions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-732: Incorrect Permission Assignment."""
        patterns = [
            # Overly permissive file permissions
            (r'chmod\s*\([^,]*,\s*0?[67]77', 'World-writable file permissions'),
            (r'os\.chmod\s*\([^,]*,\s*0o?[67]77', 'World-writable file permissions'),
            (r'umask\s*\(\s*0+\s*\)', 'Permissive umask (000)'),
            # Directory permissions
            (r'mkdir\s*\([^,]*,\s*0?777', 'World-writable directory'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-732',
                        severity='medium',
                        title='Incorrect Permission Assignment',
                        description=f'{desc}. Use restrictive file permissions (e.g., 0644 or 0600).',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def _is_comment(self, line: str) -> bool:
        """Check if line is a comment (basic check for common languages)."""
        stripped = line.strip()
        return (
            stripped.startswith('#') or
            stripped.startswith('//') or
            stripped.startswith('/*') or
            stripped.startswith('*') or
            stripped.startswith('<!--')
        )


