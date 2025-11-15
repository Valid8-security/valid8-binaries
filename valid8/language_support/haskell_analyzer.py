"""
Haskell language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class HaskellAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Haskell code."""

    def __init__(self):
        super().__init__()
        self.language = "haskell"

    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-94',   # Code Injection
            'CWE-200',  # Information Exposure
            'CWE-287',  # Improper Authentication
            'CWE-798',  # Hardcoded Credentials
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Haskell code."""
        vulnerabilities = []

        vulnerabilities.extend(self.detect_command_injection_haskell(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection_haskell(code, filepath))
        vulnerabilities.extend(self.detect_code_injection_haskell(code, filepath))
        vulnerabilities.extend(self.detect_xss_haskell(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_credentials_haskell(code, filepath))

        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))

        return vulnerabilities

    def detect_command_injection_haskell(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in Haskell."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'callProcess\s*.*\$', "CWE-78", "critical"),
            (r'callCommand\s*.*\$', "CWE-78", "critical"),
            (r'runCommand\s*.*\$', "CWE-78", "critical"),
            (r'spawnProcess\s*.*\$', "CWE-78", "critical"),
            (r'readProcess\s*.*\$', "CWE-78", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|validate|sanitize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Command Injection",
                            description="User-controlled input flows into command execution.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_sql_injection_haskell(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Haskell."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'query\s*.*\$', "CWE-89", "critical"),
            (r'execute\s*.*\$', "CWE-89", "critical"),
            (r'execute_\s*.*\$', "CWE-89", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote|bind', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="SQL Injection",
                            description="Database query constructed with unsanitised user input.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_code_injection_haskell(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect code injection in Haskell."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'interpret\s*.*\$', "CWE-94", "critical"),
            (r'eval\s*.*\$', "CWE-94", "critical"),
            (r'compileExpr\s*.*\$', "CWE-94", "critical"),
            (r'dynCompileExpr\s*.*\$', "CWE-94", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity,
                        title="Code Injection",
                        description="Dynamic code execution with user-controlled input.",
                        file_path=filepath, line_number=i,
                        code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

    def detect_xss_haskell(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Haskell web applications."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'html\s*.*\$', "CWE-79", "high"),
            (r'blazeHtml\s*.*\$', "CWE-79", "high"),
            (r'lucid\s*.*\$', "CWE-79", "high"),
            (r'heist\s*.*\$', "CWE-79", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
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

    def detect_hardcoded_credentials_haskell(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Haskell."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'password\s*=\s*["\'][A-Za-z0-9]{8,}["\']', "CWE-798", "critical"),
            (r'apiKey\s*=\s*["\'][A-Za-z0-9]{15,}["\']', "CWE-798", "high"),
            (r'secret\s*=\s*["\'][A-Za-z0-9]{10,}["\']', "CWE-798", "high"),
            (r'token\s*=\s*["\'][A-Za-z0-9]{20,}["\']', "CWE-798", "high"),
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

    def _redact_secret(self, line: str) -> str:
        """Redact secret values in code snippets."""
        return re.sub(r'["\'][A-Za-z0-9]{8,}["\']', '"***REDACTED***"', line)
