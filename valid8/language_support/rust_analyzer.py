#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Rust language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class RustAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Rust code."""
    
    def __init__(self):
        super().__init__()
        self.language = "rust"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-200',  # Information Exposure
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-327',  # Weak Crypto
            'CWE-352',  # CSRF
            'CWE-415',  # Double Free
            'CWE-416',  # Use After Free
            'CWE-476',  # NULL Pointer Dereference
            'CWE-676',  # Unsafe Functions
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Rust code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_unsafe_blocks(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        
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
        """Detect command injection in Rust."""
        patterns = [
            r'Command::new\s*\([^)]*\+',
            r'\.arg\s*\([^)]*format!',
            r'\.args\s*\(&\[.*\+',
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
                        description='Command injection. Use separate arguments with .arg() or .args().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Rust."""
        patterns = [
            r'\.execute\s*\(&format!',
            r'\.query\s*\(&format!',
            r'\.query_as\s*\(&format!',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='SQL Injection',
                        description='Potential SQL injection. Use parameterized queries with sqlx or diesel.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_blocks(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe blocks in Rust."""
        patterns = [
            r'\bunsafe\s+{',
            r'\bunsafe\s+fn',
            r'\.unwrap_unchecked\(\)',
            r'from_raw_parts',
            r'transmute',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-676',
                        severity='medium',
                        title='Unsafe Code Block',
                        description='Unsafe code requires careful review. Document safety invariants.',
                        code=code,
                        filepath=filepath,
                        line_number=i,
                        confidence='medium'
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in Rust."""
        patterns = [
            (r'Md5::new\s*\(\)', 'MD5'),
            (r'Sha1::new\s*\(\)', 'SHA1'),
            (r'use\s+md5::', 'MD5'),
            (r'use\s+sha1::', 'SHA1'),
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
                        description=f'Weak algorithm {algo}. Use sha2::Sha256 or ring crate.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Rust."""
        patterns = [
            (r'let\s+password\s*=\s*"[^"]{3,}"', 'password'),
            (r'let\s+api_key\s*=\s*"[^"]{10,}"', 'API key'),
            (r'const\s+SECRET\s*:\s*&str\s*=\s*"', 'secret'),
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
                        description=f'Hardcoded {cred_type}. Use std::env::var() for secrets.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Rust."""
        patterns = [
            r'File::open\s*\([^)]*\+',
            r'Path::new\s*\([^)]*\+',
            r'fs::read\s*\([^)]*\+',
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
                        description='Potential path traversal. Validate paths with canonicalize().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities


