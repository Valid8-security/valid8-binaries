"""
Bash/Shell language security analyzer.
"""

import re
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors


class BashAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Bash/Shell scripts."""

    def __init__(self):
        super().__init__()
        self.language = "bash"

    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS (in web contexts)
            'CWE-89',   # SQL Injection (in database scripts)
            'CWE-94',   # Code Injection
            'CWE-200',  # Information Exposure
            'CWE-287',  # Improper Authentication
            'CWE-798',  # Hardcoded Credentials
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Bash/Shell code."""
        vulnerabilities = []

        vulnerabilities.extend(self.detect_command_injection_bash(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection_bash(code, filepath))
        vulnerabilities.extend(self.detect_code_injection_bash(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_credentials_bash(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal_bash(code, filepath))
        vulnerabilities.extend(self.detect_weak_permissions_bash(code, filepath))

        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))

        return vulnerabilities

    def detect_command_injection_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in Bash."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'`.*\$', "CWE-78", "critical"),  # Backticks with variables
            (r'\$\(.*\$', "CWE-78", "critical"),  # Command substitution with variables
            (r'eval\s+.*\$', "CWE-78", "critical"),  # eval with variables
            (r'bash\s+-c\s+.*\$', "CWE-78", "critical"),  # bash -c with variables
            (r'sh\s+-c\s+.*\$', "CWE-78", "critical"),  # sh -c with variables
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Command Injection",
                            description="User-controlled input flows into command execution.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_sql_injection_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Bash database scripts."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'mysql\s+.*\$', "CWE-89", "critical"),
            (r'psql\s+.*\$', "CWE-89", "critical"),
            (r'sqlite3\s+.*\$', "CWE-89", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote|bind', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="SQL Injection",
                            description="Database command constructed with unsanitised user input.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

    def detect_code_injection_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect code injection in Bash."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'source\s+.*\$', "CWE-94", "high"),  # sourcing files with variables
            (r'\.\s+.*\$', "CWE-94", "high"),  # dot sourcing with variables
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
                        confidence="medium", category="injection"
                    ))
        return vulnerabilities

    def detect_hardcoded_credentials_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Bash."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'PASSWORD\s*=\s*["\'][A-Za-z0-9]{8,}["\']', "CWE-798", "critical"),
            (r'API_KEY\s*=\s*["\'][A-Za-z0-9]{15,}["\']', "CWE-798", "high"),
            (r'SECRET\s*=\s*["\'][A-Za-z0-9]{10,}["\']', "CWE-798", "high"),
            (r'TOKEN\s*=\s*["\'][A-Za-z0-9]{20,}["\']', "CWE-798", "high"),
            (r'DB_PASS\s*=\s*["\'][A-Za-z0-9]{8,}["\']', "CWE-798", "critical"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    if not any(skip in line.lower() for skip in ['example', 'placeholder', 'test', 'xxx']):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Hardcoded Credentials",
                            description="Hardcoded credentials detected in shell script.",
                            file_path=filepath, line_number=i,
                            code_snippet=self._redact_secret(line.strip()),
                            confidence="high", category="secrets"
                        ))
        return vulnerabilities

    def detect_path_traversal_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Bash."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'cat\s+.*\$', "CWE-22", "high"),
            (r'cp\s+.*\$', "CWE-22", "high"),
            (r'mv\s+.*\$', "CWE-22", "high"),
            (r'rm\s+.*\$', "CWE-22", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'file|path|input', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity,
                            title="Path Traversal",
                            description="File operations with user-controlled paths.",
                            file_path=filepath, line_number=i,
                            code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

    def detect_weak_permissions_bash(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak file permissions in Bash."""
        vulnerabilities = []
        lines = code.split('\n')

        patterns = [
            (r'chmod\s+777', "CWE-732", "high"),
            (r'chmod\s+666', "CWE-732", "medium"),
            (r'umask\s+0', "CWE-732", "high"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity,
                        title="Incorrect Permission Assignment",
                        description="Overly permissive file permissions or umask.",
                        file_path=filepath, line_number=i,
                        code_snippet=line.strip(),
                        confidence="high", category="permissions"
                    ))
        return vulnerabilities

    def _redact_secret(self, line: str) -> str:
        """Redact secret values in code snippets."""
        return re.sub(r'["\'][A-Za-z0-9]{8,}["\']', '"***REDACTED***"', line)
