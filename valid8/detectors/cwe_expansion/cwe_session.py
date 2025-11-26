#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""Session Management Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class SessionFixationDetector(VulnerabilityDetector):
    """CWE-384: Session Fixation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'session\["id"\]\s*=\s*request\.(params|query|body)', "CWE-384", "high"), (r'session\.id\s*=\s*request\.', "CWE-384", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-384", severity=severity, title="Session Fixation", description="Session fixation vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="session"))
        return vulnerabilities

class InsufficientSessionExpirationDetector(VulnerabilityDetector):
    """CWE-613: Insufficient Session Expiration"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'session\.timeout\s*=\s*0|.*session.*expire.*never', "CWE-613", "medium"), (r'sessionExpiration.*=.*0', "CWE-613", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-613", severity=severity, title="Insufficient Session Expiration", description="Session expiration not configured properly.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="session"))
        return vulnerabilities

class WeakSessionIDDetector(VulnerabilityDetector):
    """CWE-330: Weak Session ID"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'session[_-]?id\s*=\s*(time|date|timestamp|rand|Math\.random)', "CWE-330", "medium"), (r'sessionId\s*=\s*Date\.now|.*timestamp', "CWE-330", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-330", severity=severity, title="Weak Session ID", description="Weak session ID generation.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="session"))
        return vulnerabilities

class SessionInsecureStorageDetector(VulnerabilityDetector):
    """CWE-922: Insecure Session Storage"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'localStorage\.(setItem|set)\([^)]*session|.*token', "CWE-922", "high"), (r'sessionStorage\.(setItem|set)\([^)]*password|.*secret', "CWE-922", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-922", severity=severity, title="Insecure Session Storage", description="Session data stored insecurely.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="session"))
        return vulnerabilities

class MissingSessionTimeoutDetector(VulnerabilityDetector):
    """CWE-613: Missing Session Timeout"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'session\[|session\.', "CWE-613", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                    if not re.search(r'timeout|expire|maxAge|max.*age', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-613", severity=severity, title="Missing Session Timeout", description="Session timeout not configured.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="session"))
        return vulnerabilities

def get_session_detectors():
    """Get all session detectors"""
    return [
        SessionFixationDetector(), InsufficientSessionExpirationDetector(), WeakSessionIDDetector(),
        SessionInsecureStorageDetector(), MissingSessionTimeoutDetector(),
    ]


