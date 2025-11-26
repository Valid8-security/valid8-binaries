#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

import re
from typing import List
from .scanner import Vulnerability

class IDORDetector:
    """🚀 ADVANCED: IDOR (Insecure Direct Object Reference) Detector."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def detect_idor_vulnerabilities(self, code: str):
        """Detect IDOR vulnerabilities in code."""
        vulnerabilities = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Check for direct object access with user input
            if self._is_potential_idor_access(line):
                # Look for missing authorization in surrounding context
                context_auth = self._check_context_authorization(lines, i)

                if not context_auth['has_authorization']:
                    vuln = Vulnerability(
                        cwe="CWE-639",
                        severity="high",
                        title="IDOR: Insecure Direct Object Reference",
                        description=f"Direct object access without proper authorization: {context_auth['reason']}",
                        file_path=self.filepath,
                        line_number=i,
                        code_snippet=line,
                        confidence=0.85
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_potential_idor_access(self, line: str) -> bool:
        """Check if line contains potential IDOR access pattern."""
        idor_patterns = [
            r'get_user\(\w+\)', r'find_user\(\w+\)', r'user_by_id\(\w+\)',
            r'get_post\(\w+\)', r'find_post\(\w+\)', r'post_by_id\(\w+\)',
        ]
        input_patterns = [
            r'request\.args\.get', r'request\.form\[', r'request\.GET\[',
        ]
        
        has_access = any(re.search(pattern, line, re.IGNORECASE) for pattern in idor_patterns)
        has_input = any(re.search(pattern, line, re.IGNORECASE) for pattern in input_patterns)

        return has_access and has_input

    def _check_context_authorization(self, lines: List[str], line_number: int):
        """Check if there's proper authorization context around the access."""
        start_line = max(0, line_number - 10)
        end_line = min(len(lines), line_number + 5)
        context_lines = lines[start_line:end_line]

        result = {
            'has_authorization': False,
            'reason': 'No authorization check found'
        }

        # Check for authorization patterns
        auth_indicators = [
            'if user.id ==', 'if current_user.id ==', 'if session.get',
            '@login_required', '@auth_required'
        ]

        for context_line in context_lines:
            if any(indicator in context_line.lower() for indicator in auth_indicators):
                result['has_authorization'] = True
                result['reason'] = 'Authorization check found'
                break

        return result


class SSRFDetector:
    """🚀 ADVANCED: SSRF (Server-Side Request Forgery) Detector."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def detect_ssrf_vulnerabilities(self, code: str):
        """Detect SSRF vulnerabilities in code."""
        vulnerabilities = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Check for URL fetching with user input
            has_fetch = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'requests\.get\(', r'requests\.post\(',
                r'urllib\.request\.urlopen'
            ])
            has_input = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'request\.args\.get\(.*url', r'request\.form\[.*url'
            ])

            if has_fetch and has_input:
                vuln = Vulnerability(
                    cwe="CWE-918",
                    severity="critical",
                    title="SSRF: Server-Side Request Forgery",
                    description="URL fetching based on user input without proper validation",
                    file_path=self.filepath,
                    line_number=i,
                    code_snippet=line,
                    confidence=0.9
                )
                vulnerabilities.append(vuln)

        return vulnerabilities


class XXEDetector:
    """🚀 ADVANCED: XXE (XML External Entity) Detector."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def detect_xxe_vulnerabilities(self, code: str):
        """Detect XXE vulnerabilities in code."""
        vulnerabilities = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Check for XML parsing
            has_xml_parsing = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'xml\.etree\.ElementTree', r'lxml\.etree',
                r'minidom\.parse', r'ET\.parse'
            ])

            if has_xml_parsing:
                vuln = Vulnerability(
                    cwe="CWE-611",
                    severity="critical",
                    title="XXE: XML External Entity Processing",
                    description="XML parsing that may allow external entity processing",
                    file_path=self.filepath,
                    line_number=i,
                    code_snippet=line,
                    confidence=0.95
                )
                vulnerabilities.append(vuln)

        return vulnerabilities


class CSRFDetector:
    """🚀 ADVANCED: CSRF (Cross-Site Request Forgery) Detector."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def detect_csrf_vulnerabilities(self, code: str):
        """Detect CSRF vulnerabilities in code."""
        vulnerabilities = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Check for state-changing operations
            is_state_changing = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'def\s+(create|update|delete|post|put|patch)',
                r'@app\.route.*methods.*POST'
            ])

            if is_state_changing:
                # Check for CSRF protection in context
                has_csrf_protection = self._check_csrf_protection(lines, i)

                if not has_csrf_protection['protected']:
                    vuln = Vulnerability(
                        cwe="CWE-352",
                        severity="high",
                        title="CSRF: Cross-Site Request Forgery",
                        description=f"State-changing operation without CSRF protection: {has_csrf_protection['reason']}",
                        file_path=self.filepath,
                        line_number=i,
                        code_snippet=line,
                        confidence=0.85
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_csrf_protection(self, lines: List[str], line_number: int):
        """Check if there's CSRF protection in context."""
        start_line = max(0, line_number - 15)
        end_line = min(len(lines), line_number + 5)
        context_lines = lines[start_line:end_line]

        result = {
            'protected': False,
            'reason': 'No CSRF protection found'
        }

        # Check for CSRF tokens
        for line in context_lines:
            if re.search(r'csrf_token', line, re.IGNORECASE):
                result['protected'] = True
                result['reason'] = 'CSRF token found'
                return result

        return result


class InformationDisclosureDetector:
    """🚀 ADVANCED: Information Disclosure Detector."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def detect_information_disclosure(self, code: str):
        """Detect information disclosure vulnerabilities."""
        vulnerabilities = []
        lines = code.split("\n")

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Check for sensitive data in output
            has_sensitive = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'password', r'secret', r'key', r'token', r'api_key'
            ])
            has_output = any(re.search(pattern, line, re.IGNORECASE) for pattern in [
                r'print\(', r'return.*\{', r'console\.log\('
            ])

            if has_sensitive and has_output:
                vuln = Vulnerability(
                    cwe="CWE-200",
                    severity="medium",
                    title="Information Disclosure: Sensitive Data Exposure",
                    description="Sensitive data exposed in output",
                    file_path=self.filepath,
                    line_number=i,
                    code_snippet=line,
                    confidence=0.8
                )
                vulnerabilities.append(vuln)

        return vulnerabilities
