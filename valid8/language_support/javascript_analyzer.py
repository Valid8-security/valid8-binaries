#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
JavaScript/TypeScript language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class JavaScriptAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for JavaScript and TypeScript code."""
    
    def __init__(self):
        super().__init__()
        self.language = "javascript"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-94',   # Code Injection (eval)
            'CWE-95',   # Dynamic Code Injection (dangerous functions)
            'CWE-200',  # Information Exposure
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-295',  # Improper Certificate Validation
            'CWE-319',  # Cleartext Transmission
            'CWE-321',  # Hard-coded Cryptographic Key
            'CWE-327',  # Weak Crypto
            'CWE-352',  # CSRF
            'CWE-502',  # Unsafe Deserialization
            'CWE-601',  # Open Redirect
            'CWE-611',  # XXE
            'CWE-614',  # Insecure Cookie
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
            'CWE-915',  # Prototype Pollution
            'CWE-918',  # SSRF
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze JavaScript/TypeScript code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_xss(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_unsafe_deserialization(code, filepath))
        vulnerabilities.extend(self.detect_ssrf(code, filepath))
        vulnerabilities.extend(self.detect_prototype_pollution(code, filepath))
        vulnerabilities.extend(self.detect_dangerous_functions(code, filepath))
        
        # NEW: Extended CWE detection methods
        vulnerabilities.extend(self.detect_weak_ssl_js(code, filepath))
        vulnerabilities.extend(self.detect_insecure_http_js(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_key_js(code, filepath))
        vulnerabilities.extend(self.detect_insecure_cookie_js(code, filepath))
        
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
        """Detect command injection in JavaScript."""
        patterns = [
            (r'child_process\.exec\s*\([^)]*\+', 'exec with concatenation'),
            (r'child_process\.execSync\s*\([^)]*\+', 'execSync with concatenation'),
            (r'\.exec\s*\(\s*`.*\$\{', 'exec with template literal'),
            (r'spawn\s*\([^)]*\+', 'spawn with concatenation'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, method in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description=f'Command injection via {method}. Use parameterized commands or execFile.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE SQL injection detection - catch everything that queries databases."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY database operation that could involve user input
        patterns = [
            # Original conservative patterns
            r'\.query\s*\(\s*["\'].*\+',
            r'\.query\s*\(\s*`.*\$\{',
            r'\.execute\s*\(\s*["\'].*\+',
            r'\.raw\s*\(\s*["\'].*\+',
            r'sequelize\.query\s*\(\s*`',

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any database query method
            r'\.query\s*\(',
            r'\.execute\s*\(',
            r'\.raw\s*\(',
            r'\.run\s*\(',
            r'\.all\s*\(',
            r'\.get\s*\(',
            r'\.find\s*\(',
            r'\.findOne\s*\(',
            r'\.findAll\s*\(',
            r'\.create\s*\(',
            r'\.update\s*\(',
            r'\.delete\s*\(',

            # ORM methods
            r'sequelize\.query\s*\(',
            r'mongoose\.model',
            r'prisma\.',
            r'typeorm\.',

            # Any string concatenation near database calls
            r'query\s*\(.*\+',
            r'execute\s*\(.*\+',
            r'\+\s*query',
            r'\+\s*execute',

            # Any user input near database calls
            r'req\.query.*query',
            r'req\.body.*query',
            r'req\.params.*query',
            r'req\.query.*execute',
            r'req\.body.*execute',

            # Any variable in SQL context
            r'query\s*\(\s*\w+\s*\)',
            r'execute\s*\(\s*\w+\s*\)',
            r'raw\s*\(\s*\w+\s*\)',

            # SQL keywords anywhere
            r'SELECT.*FROM',
            r'INSERT.*INTO',
            r'UPDATE.*SET',
            r'DELETE.*FROM',
            r'WHERE.*=',
            r'JOIN.*ON',
            r'UNION.*SELECT',

            # Database connection indicators
            r'mysql\.createConnection',
            r'pg\.connect',
            r'sqlite',
            r'mongodb',
            r'redis',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='Potential SQL Injection',
                        description='ULTRA-PERMISSIVE: Any database operation flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE XSS detection - catch everything that outputs HTML/DOM content."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY DOM manipulation that could involve user input
        patterns = [
            # Original conservative patterns
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any DOM manipulation
            r'\.innerHTML',
            r'\.outerHTML',
            r'\.innerText',
            r'\.textContent',
            r'\.value\s*=',
            r'\.src\s*=',
            r'\.href\s*=',

            # Any HTML insertion
            r'\.html\s*\(',
            r'\.append\s*\(',
            r'\.prepend\s*\(',
            r'\.after\s*\(',
            r'\.before\s*\(',
            r'\.html\s*=',
            r'\$[\(\{].*\.html',  # jQuery .html()

            # Any string concatenation near DOM
            r'innerHTML\s*\+',
            r'\+\s*innerHTML',
            r'document\.write.*\+',
            r'\+\s*document\.write',

            # Any user input access
            r'req\.query',
            r'req\.body',
            r'req\.params',
            r'window\.location',
            r'document\.cookie',
            r'localStorage',
            r'sessionStorage',

            # Any variable in DOM context
            r'innerHTML\s*=\s*\w+',
            r'document\.write\s*\(\s*\w+\s*\)',
            r'\.value\s*=\s*\w+',

            # HTML/JS injection patterns
            r'<script>',
            r'</script>',
            r'onclick',
            r'onload',
            r'onerror',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout.*\+',
            r'setInterval.*\+',

            # Template literal dangers
            r'`.*\$\{.*req',
            r'`.*\$\{.*query',
            r'`.*\$\{.*body',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-79',
                        severity='high',
                        title='Potential XSS Vulnerability',
                        description='ULTRA-PERMISSIVE: Any DOM manipulation or user input flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in JavaScript."""
        patterns = [
            r'fs\.readFile\s*\([^)]*req\.',
            r'fs\.writeFile\s*\([^)]*req\.',
            r'path\.join\s*\(__dirname[^)]*req\.',
            r'fs\.createReadStream\s*\([^)]*req\.',
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
                        description='Potential path traversal. Validate file paths and use path.normalize().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in JavaScript."""
        patterns = [
            (r'crypto\.createHash\s*\(\s*["\']md5["\']', 'MD5'),
            (r'crypto\.createHash\s*\(\s*["\']sha1["\']', 'SHA1'),
            (r'crypto\.createCipher\s*\(\s*["\']des', 'DES'),
            (r'\.createCipher\s*\(', 'createCipher (deprecated)'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, algo in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-327',
                        severity='medium',
                        title='Weak Cryptographic Algorithm',
                        description=f'Weak crypto: {algo}. Use sha256 or createCipheriv with AES.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in JavaScript."""
        patterns = [
            (r'password\s*[:=]\s*["\'][^"\']{3,}["\']', 'password'),
            (r'apiKey\s*[:=]\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*[:=]\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'token\s*[:=]\s*["\'][^"\']{10,}["\']', 'token'),
            (r'privateKey\s*[:=]\s*["\']', 'private key'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if '//' in line or '/*' in line:
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type}. Use environment variables.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization in JavaScript."""
        patterns = [
            r'JSON\.parse\s*\([^)]*req\.',
            r'eval\s*\(',
            r'Function\s*\(\s*[^)]*req',
            r'vm\.runInNewContext\s*\(',
            r'serialize\.unserialize\s*\(',
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
                        description='Unsafe deserialization of untrusted data. Validate input first.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SSRF in JavaScript."""
        patterns = [
            r'fetch\s*\([^)]*req\.',
            r'axios\.get\s*\([^)]*req\.',
            r'request\s*\([^)]*req\.',
            r'http\.get\s*\([^)]*req\.',
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
    
    def detect_prototype_pollution(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect prototype pollution in JavaScript."""
        patterns = [
            r'\[.*__proto__.*\]',
            r'\.constructor\.prototype',
            r'Object\.assign\s*\([^,]*,\s*req\.',
            r'\.merge\s*\([^)]*req\.',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-915',
                        severity='high',
                        title='Prototype Pollution',
                        description='Potential prototype pollution. Sanitize object keys.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_dangerous_functions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect dangerous functions in JavaScript."""
        patterns = [
            (r'\beval\s*\(', 'eval'),
            (r'new\s+Function\s*\(', 'Function constructor'),
            (r'setTimeout\s*\(\s*["\']', 'setTimeout with string'),
            (r'setInterval\s*\(\s*["\']', 'setInterval with string'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, func in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-95',
                        severity='high',
                        title='Dangerous Function Usage',
                        description=f'Use of dangerous function: {func}. Avoid dynamic code execution.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_ssl_js(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-295: Improper Certificate Validation in JavaScript."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'rejectUnauthorized\s*:\s*false', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-295',
                    severity='high',
                    title='Improper Certificate Validation',
                    description='SSL certificate validation disabled. Always verify certificates.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_insecure_http_js(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-319: Cleartext Transmission in JavaScript."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\"http://[^\"]+', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-319',
                    severity='high',
                    title='Cleartext Transmission',
                    description='HTTP used instead of HTTPS. Use encrypted transport.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_hardcoded_key_js(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-321: Hard-coded Cryptographic Key in JavaScript."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:const|var|let)\s+(?:SECRET|API_KEY|PRIVATE_KEY)\s*=\s*["\']', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-321',
                    severity='critical',
                    title='Hard-coded Cryptographic Key',
                    description='Hard-coded encryption key detected. Use environment variables.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_insecure_cookie_js(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-614: Insecure Cookie in JavaScript."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'document\.cookie\s*=|\.cookie\s*=', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                if 'secure' not in context.lower() or 'httponly' not in context.lower():
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-614',
                        severity='medium',
                        title='Insecure Cookie',
                        description='Cookie without Secure or HttpOnly flags. Add these flags.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities

