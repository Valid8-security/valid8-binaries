#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
PHP language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class PHPAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for PHP code."""
    
    def __init__(self):
        super().__init__()
        self.language = "php"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-98',   # Remote File Inclusion
            'CWE-200',  # Information Exposure
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-327',  # Weak Crypto
            'CWE-352',  # CSRF
            'CWE-502',  # Unsafe Deserialization
            'CWE-601',  # Open Redirect
            'CWE-611',  # XXE
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
            'CWE-918',  # SSRF
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze PHP code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_xss(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_unsafe_deserialization(code, filepath))
        vulnerabilities.extend(self.detect_file_inclusion(code, filepath))
        vulnerabilities.extend(self.detect_dangerous_functions(code, filepath))
        
        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_csrf(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))
        vulnerabilities.extend(self.detect_graphql_security(code, filepath))
        vulnerabilities.extend(self.detect_jwt_security(code, filepath))
        vulnerabilities.extend(self.detect_nosql_injection(code, filepath))
        vulnerabilities.extend(self.detect_ssti(code, filepath))
        vulnerabilities.extend(self.detect_redos(code, filepath))
        
        return vulnerabilities
    
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in PHP."""
        patterns = [
            (r'\bshell_exec\s*\(', 'shell_exec'),
            (r'\bexec\s*\(', 'exec'),
            (r'\bsystem\s*\(', 'system'),
            (r'\bpassthru\s*\(', 'passthru'),
            (r'\bpopen\s*\(', 'popen'),
            (r'`[^`]*\$', 'backticks with variable'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, func in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description=f'Command injection via {func}. Use escapeshellarg() or parameterized commands.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in PHP."""
        patterns = [
            r'mysql_query\s*\([^)]*\$_',
            r'mysqli_query\s*\([^)]*\$_',
            r'\$pdo->query\s*\([^)]*\$_',
            r'->query\s*\([^)]*\.',
            r'SELECT.*\$_',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='SQL Injection',
                        description='Potential SQL injection. Use prepared statements with PDO or mysqli.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in PHP."""
        patterns = [
            r'echo\s+\$_',
            r'print\s+\$_',
            r'<\?=\s*\$_',
            r'printf\s*\([^)]*\$_',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if htmlspecialchars is used
                    if 'htmlspecialchars' not in line and 'htmlentities' not in line:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-79',
                            severity='high',
                            title='Cross-Site Scripting (XSS)',
                            description='User input output without escaping. Use htmlspecialchars().',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in PHP."""
        patterns = [
            r'fopen\s*\([^)]*\$_',
            r'file_get_contents\s*\([^)]*\$_',
            r'include\s+\$_',
            r'require\s+\$_',
            r'readfile\s*\([^)]*\$_',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-22',
                        severity='high',
                        title='Path Traversal',
                        description='Potential path traversal. Validate and sanitize file paths with basename().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in PHP."""
        patterns = [
            (r'\bmd5\s*\(', 'MD5'),
            (r'\bsha1\s*\(', 'SHA1'),
            (r'mcrypt_', 'mcrypt (deprecated)'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, algo in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-327',
                        severity='medium',
                        title='Weak Cryptographic Algorithm',
                        description=f'Weak crypto: {algo}. Use password_hash() or hash("sha256").',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in PHP."""
        patterns = [
            (r'\$password\s*=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'\$api_key\s*=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'\$secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'define\s*\(\s*["\'].*PASSWORD', 'password constant'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if '//' in line or '#' in line:
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type}. Use $_ENV or getenv().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization in PHP."""
        patterns = [
            r'\bunserialize\s*\([^)]*\$_',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-502',
                        severity='high',
                        title='Unsafe Deserialization',
                        description='Unsafe deserialization. Use JSON instead of serialize().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_file_inclusion(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect file inclusion vulnerabilities."""
        patterns = [
            r'include\s*\([^)]*\$_',
            r'include_once\s*\([^)]*\$_',
            r'require\s*\([^)]*\$_',
            r'require_once\s*\([^)]*\$_',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-98',
                        severity='critical',
                        title='Remote File Inclusion',
                        description='File inclusion with user input. Whitelist allowed files.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_dangerous_functions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect dangerous PHP functions."""
        patterns = [
            (r'\beval\s*\(', 'eval'),
            (r'\bassert\s*\([^)]*\$', 'assert with variable'),
            (r'\bcreate_function\s*\(', 'create_function'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, func in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-95',
                        severity='critical',
                        title='Dangerous Function Usage',
                        description=f'Dangerous function: {func}. Avoid dynamic code execution.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities


