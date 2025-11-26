#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""Cross-Site Scripting (XSS) Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector
from valid8.detectors.base_detector import regex_pool  # 🚀 REGEX POOL OPTIMIZATION

class XSSDetector(VulnerabilityDetector):
    """CWE-79: Cross-site Scripting (XSS)"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'innerHTML.*\+', "CWE-79", "high"),
            (r'document\.write.*\+', "CWE-79", "high"),
            (r'\.html\(.*\+', "CWE-79", "high"),
            (r'outerHTML.*\+', "CWE-79", "high"),
            (r'insertAdjacentHTML.*\+', "CWE-79", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not regex_pool.get_compiled(r'escape|sanitize|encode').search(context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Cross-Site Scripting (XSS)",
                            description="XSS vulnerability. Use proper output encoding or sanitization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="xss"
                        ))
        return vulnerabilities

class DOMBasedXSSDetector(VulnerabilityDetector):
    """CWE-83: DOM-based XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'location\.hash', "CWE-83", "high"),
            (r'location\.search', "CWE-83", "high"),
            (r'document\.location', "CWE-83", "high"),
            (r'window\.location', "CWE-83", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                    if regex_pool.get_compiled(r'innerHTML|outerHTML|document\.write|eval').search(context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="DOM-based XSS",
                            description="DOM-based XSS vulnerability. Sanitize location data before use.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="xss"
                        ))
        return vulnerabilities

class ReflectedXSSDetector(VulnerabilityDetector):
    """CWE-87: Reflected XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'echo.*\$_GET', "CWE-87", "high"),
            (r'echo.*\$_POST', "CWE-87", "high"),
            (r'echo.*\$_REQUEST', "CWE-87", "high"),
            (r'print.*param', "CWE-87", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not regex_pool.get_compiled(r'htmlentities|htmlspecialchars|escape').search(context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Reflected XSS",
                            description="Reflected XSS vulnerability. Escape output properly.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="xss"
                        ))
        return vulnerabilities

class StoredXSSDetector(VulnerabilityDetector):
    """CWE-80: Stored XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'INSERT.*INTO.*comment', "CWE-80", "high"),
            (r'INSERT.*INTO.*message', "CWE-80", "high"),
            (r'INSERT.*INTO.*post', "CWE-80", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])
                    if not regex_pool.get_compiled(r'htmlentities|strip_tags|sanitize').search(context):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Stored XSS",
                            description="Stored XSS vulnerability. Sanitize data before storing in database.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="xss"
                        ))
        return vulnerabilities

class BlindXSSDetector(VulnerabilityDetector):
    """CWE-81: Blind XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'mail\(.*\$', "CWE-81", "medium"),
            (r'sendmail.*\$', "CWE-81", "medium"),
            (r'email.*\$', "CWE-81", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'strip_tags|sanitize|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Blind XSS",
                            description="Blind XSS in email content. Sanitize email data.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="xss"
                        ))
        return vulnerabilities

class FilterBypassXSSDetector(VulnerabilityDetector):
    """CWE-82: Filter Bypass XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'on\w+\s*=.*<script', "CWE-82", "high"),
            (r'javascript:.*<script', "CWE-82", "high"),
            (r'vbscript:.*<script', "CWE-82", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Filter Bypass XSS",
                        description="XSS filter bypass attempt. Use proper input validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="xss"
                    ))
        return vulnerabilities

class SelfXSSDetector(VulnerabilityDetector):
    """CWE-79: Self-XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'console\.log.*\+', "CWE-79", "low"),
            (r'document\.cookie.*\+', "CWE-79", "medium"),
            (r'localStorage.*\+', "CWE-79", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if re.search(r'user.*input|param|get', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Self-XSS",
                            description="Self-XSS vulnerability. Validate input before storage/display.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="xss"
                        ))
        return vulnerabilities

class MXXSSDetector(VulnerabilityDetector):
    """CWE-79: Mutation XSS (mXSS)"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.innerHTML.*=.*replace', "CWE-79", "high"),
            (r'\.outerHTML.*=.*replace', "CWE-79", "high"),
            (r'html.*=.*replace', "CWE-79", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+5)])
                    if re.search(r'user|input|param', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Mutation XSS (mXSS)",
                            description="Mutation XSS vulnerability. Be careful with string replacements in HTML.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="xss"
                        ))
        return vulnerabilities

class ClientSideXSSDetector(VulnerabilityDetector):
    """CWE-79: Client-side XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'eval\(.*location', "CWE-79", "critical"),
            (r'Function\(.*location', "CWE-79", "critical"),
            (r'setTimeout\(.*location', "CWE-79", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Client-side XSS",
                        description="Client-side XSS through code execution. Never eval location data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="critical", category="xss"
                    ))
        return vulnerabilities

class TemplateXSSDetector(VulnerabilityDetector):
    """CWE-79: Template XSS"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\{\{.*\}\}', "CWE-79", "medium"),
            (r'\{\%\s*.*\s*\%\}', "CWE-79", "medium"),
            (r'\{\{\{.*\}\}\}', "CWE-79", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if regex_pool.get_compiled(pattern).search(line):
                    context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                    if re.search(r'user|input|param|request', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Template XSS",
                            description="Template XSS vulnerability. Use auto-escaping or manual escaping.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="xss"
                        ))
        return vulnerabilities

def get_xss_detectors():
    """Get all XSS detectors"""
    return [
        XSSDetector(),
        DOMBasedXSSDetector(),
        ReflectedXSSDetector(),
        StoredXSSDetector(),
        BlindXSSDetector(),
        FilterBypassXSSDetector(),
        SelfXSSDetector(),
        MXXSSDetector(),
        ClientSideXSSDetector(),
        TemplateXSSDetector(),
    ]