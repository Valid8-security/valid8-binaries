"""
Ruby language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class RubyAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Ruby code (including Rails)."""
    
    def __init__(self):
        super().__init__()
        self.language = "ruby"
    
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
            'CWE-502',  # Unsafe Deserialization
            'CWE-601',  # Open Redirect
            'CWE-611',  # XXE
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
            'CWE-918',  # SSRF
            'CWE-1321', # Improperly Controlled Modification (Mass Assignment)
        ]
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Ruby code."""
        vulnerabilities = []
        
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_xss(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_unsafe_deserialization(code, filepath))
        vulnerabilities.extend(self.detect_mass_assignment(code, filepath))
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
        """Detect command injection in Ruby."""
        patterns = [
            (r'system\s*\(', 'system'),
            (r'exec\s*\(', 'exec'),
            (r'`[^`]*#\{', 'backticks with interpolation'),
            (r'%x\[.*#\{', '%x with interpolation'),
            (r'Open3\.', 'Open3 module'),
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
                        description=f'Command injection via {method}. Use array form or Open3.capture3.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Ruby."""
        patterns = [
            r'\.where\s*\(\s*["\'][^"\']*#\{',
            r'\.find_by_sql\s*\(\s*["\'][^"\']*#\{',
            r'\.execute\s*\(\s*["\'][^"\']*#\{',
            r'ActiveRecord.*\.where\s*\(\s*["\'][^"\']*\+',
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
                        description='Potential SQL injection. Use parameterized queries with placeholders.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Ruby/Rails."""
        patterns = [
            r'raw\s*\(',
            r'html_safe',
            r'content_tag\s*\([^)]*\.html_safe',
            r'render\s+:inline',
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
                        description='Potential XSS. Use Rails auto-escaping or sanitize helper.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Ruby."""
        patterns = [
            r'File\.open\s*\([^)]*params\[',
            r'File\.read\s*\([^)]*params\[',
            r'IO\.read\s*\([^)]*params\[',
            r'send_file\s*\([^)]*params\[',
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
                        description='Potential path traversal. Validate paths with File.basename().',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in Ruby."""
        patterns = [
            (r'Digest::MD5', 'MD5'),
            (r'Digest::SHA1', 'SHA1'),
            (r'OpenSSL::Cipher::.*DES', 'DES'),
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
                        description=f'Weak algorithm {algo}. Use Digest::SHA256 or bcrypt.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Ruby."""
        patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'api_key\s*=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'SECRET\s*=\s*["\']', 'secret constant'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if '#' in line:
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type}. Use ENV[] or Rails credentials.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization in Ruby."""
        patterns = [
            r'Marshal\.load\s*\(',
            r'YAML\.load\s*\([^)]*params',
            r'\.to_yaml\.load',
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
                        description='Unsafe deserialization. Use YAML.safe_load() or JSON.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_mass_assignment(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect mass assignment vulnerabilities in Rails."""
        patterns = [
            r'\.new\s*\(params\[',
            r'\.create\s*\(params\[',
            r'\.update_attributes\s*\(params\[',
            r'\.update\s*\(params\[',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if strong parameters are used
                    code_window = '\n'.join(lines[max(0, i-10):i])
                    if 'permit' not in code_window:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-1321',
                            severity='high',
                            title='Mass Assignment',
                            description='Mass assignment without strong parameters. Use .permit() to whitelist.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_dangerous_functions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect dangerous functions in Ruby."""
        patterns = [
            (r'\beval\s*\(', 'eval'),
            (r'instance_eval\s*\(', 'instance_eval'),
            (r'class_eval\s*\(', 'class_eval'),
            (r'module_eval\s*\(', 'module_eval'),
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
                        description=f'Dangerous function: {func}. Avoid dynamic code evaluation.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities


