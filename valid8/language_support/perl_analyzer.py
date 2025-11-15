"""
Perl language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class PerlAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Perl code."""

    def __init__(self):
        super().__init__()
        self.language = "perl"

    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-90',   # LDAP Injection
            'CWE-134',  # Format String
            'CWE-200',  # Information Exposure
            'CWE-287',  # Improper Authentication
            'CWE-798',  # Hardcoded Credentials
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Perl code."""
        vulnerabilities = []

        vulnerabilities.extend(self.detect_command_injection_perl(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection_perl(code, filepath))
        vulnerabilities.extend(self.detect_xss_perl(code, filepath))
        vulnerabilities.extend(self.detect_format_string_perl(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_credentials_perl(code, filepath))
        vulnerabilities.extend(self.detect_ldap_injection_perl(code, filepath))

        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))

        return vulnerabilities

    def detect_command_injection_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'system\s*\([^)]*\$', "CWE-78", "critical"),
            (r'exec\s*\([^)]*\$', "CWE-78", "critical"),
            (r'qx\s*\([^)]*\$', "CWE-78", "critical"),
            (r'`.*\$', "CWE-78", "critical"),
            (r'open\s*\([^)]*\$', "CWE-78", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'quotemeta|escape|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Command Injection",
                            description="User-controlled input flows into command execution.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_sql_injection_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'do\s*\([^)]*\$', "CWE-89", "critical"),
            (r'prepare\s*\([^)]*\$', "CWE-89", "critical"),
            (r'execute\s*\([^)]*\$', "CWE-89", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'quote|placeholder|bind', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="SQL Injection",
                            description="Database query constructed with unsanitised user input.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_xss_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'print\s*.*\$', "CWE-79", "high"),
            (r'echo\s*.*\$', "CWE-79", "high"),
            (r'html\s*.*\$', "CWE-79", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'html|web|response', context, re.IGNORECASE):
                        if not re.search(r'escape|encode|sanitize', context, re.IGNORECASE):
                            vulnerabilities.append(Vulnerability(
                                cwe=cwe, severity=severity,
                                title="Cross-Site Scripting (XSS)",
                                description="HTML output includes unsanitised user input.",
                                file_path=filepath, line_number=i,
                                code_snippet=line.strip(),
                                confidence="medium", category="injection"
                            ))
        return vulnerabilities

    def detect_format_string_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect format string vulnerabilities in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'printf\s*\([^)]*\$', "CWE-134", "high"),
            (r'sprintf\s*\([^)]*\$', "CWE-134", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'%s|%d|%f', line):  # Check for proper format specifiers
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Format String Vulnerability",
                            description="User-controlled input used as format string.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

    def detect_hardcoded_credentials_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'\$password\s*=\s*["\'][A-Za-z0-9]{8,}["\']', "CWE-798", "critical"),
            (r'\$api_key\s*=\s*["\'][A-Za-z0-9]{15,}["\']', "CWE-798", "high"),
            (r'\$secret\s*=\s*["\'][A-Za-z0-9]{10,}["\']', "CWE-798", "high"),
            (r'\$token\s*=\s*["\'][A-Za-z0-9]{20,}["\']', "CWE-798", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    if not any(skip in line.lower() for skip in ['example', 'placeholder', 'test', 'xxx']):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Hardcoded Credentials",
                            description="Hardcoded credentials detected in source code.",
                            file_path=filepath, line_number=i,
                            code_snippet=self._redact_secret(line.strip()),
                            confidence="high", category="secrets"
                        ))
        return vulnerabilities

    def detect_ldap_injection_perl(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect LDAP injection in Perl."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'ldap_search\s*\([^)]*\$', "CWE-90", "high"),
            (r'bind\s*\([^)]*\$', "CWE-90", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|filter', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="LDAP Injection",
                            description="LDAP query constructed with unsanitised user input.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

    def _redact_secret(self, line: str) -> str:
        """Redact secret values in code snippets."""
        return re.sub(r'["\'][A-Za-z0-9]{8,}["\']', '"***REDACTED***"', line)
