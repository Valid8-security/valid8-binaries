#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Go language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class GoAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Go code."""
    
    def __init__(self):
        super().__init__()
        self.language = "go"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-190',  # Integer Overflow
            'CWE-200',  # Information Exposure
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-327',  # Weak Crypto
            'CWE-352',  # CSRF
            'CWE-362',  # Race Condition
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
            'CWE-918',  # SSRF
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Go code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_xss(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_ssrf(code, filepath))
        vulnerabilities.extend(self.detect_race_conditions(code, filepath))
        
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
        """Detect command injection in Go."""
        patterns = [
            r'exec\.Command\s*\([^)]*\+',
            r'exec\.CommandContext\s*\([^)]*\+',
            r'syscall\.Exec\s*\([^)]*\+',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description='Command injection. Use separate arguments instead of string concatenation.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Go."""
        patterns = [
            r'\.Query\s*\(\s*["\'].*\+',
            r'\.Exec\s*\(\s*["\'].*\+',
            r'fmt\.Sprintf\s*\([^)]*SELECT',
            r'\.QueryRow\s*\(\s*["\'].*\+',
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
                        description='Potential SQL injection. Use parameterized queries with placeholders.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Go."""
        patterns = [
            r'template\.HTML\s*\(',
            r'template\.JS\s*\(',
            r'\.Write\s*\(\[\]byte\(',
            r'fmt\.Fprintf\s*\(w,',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-79',
                        severity='high',
                        title='Cross-Site Scripting (XSS)',
                        description='Potential XSS. Use html/template auto-escaping.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Go."""
        patterns = [
            r'os\.Open\s*\([^)]*r\.',
            r'ioutil\.ReadFile\s*\([^)]*r\.',
            r'filepath\.Join\s*\([^)]*r\.',
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
                        description='Potential path traversal. Validate and sanitize file paths with filepath.Clean().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in Go."""
        patterns = [
            (r'md5\.New\s*\(\)', 'MD5'),
            (r'sha1\.New\s*\(\)', 'SHA1'),
            (r'des\.NewCipher', 'DES'),
            (r'rc4\.NewCipher', 'RC4'),
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
                        description=f'Weak algorithm {algo}. Use crypto/sha256 or AES.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Go."""
        patterns = [
            (r'password\s*:=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'apiKey\s*:=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*:=\s*["\'][^"\']{10,}["\']', 'secret'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if '//' in line:
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type}. Use os.Getenv() for secrets.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SSRF in Go."""
        patterns = [
            r'http\.Get\s*\([^)]*r\.',
            r'http\.Post\s*\([^)]*r\.',
            r'\.Do\s*\(.*Request.*r\.',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-918',
                        severity='high',
                        title='Server-Side Request Forgery (SSRF)',
                        description='Potential SSRF. Validate and whitelist URLs.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_race_conditions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect race conditions in Go."""
        patterns = [
            r'go\s+func\s*\(',
            r'go\s+\w+\s*\(',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check for shared data access
                    code_window = '\n'.join(lines[max(0,i-5):min(len(lines),i+5)])
                    if re.search(r'\w+\s*=\s*\w+', code_window) and 'sync' not in code_window.lower():
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-362',
                            severity='medium',
                            title='Race Condition',
                            description='Potential race condition. Use sync.Mutex or channels for shared data.',
                            code=code,
                            filepath=filepath,
                            line_number=i,
                            confidence='medium'
                        ))
        
        return vulnerabilities


