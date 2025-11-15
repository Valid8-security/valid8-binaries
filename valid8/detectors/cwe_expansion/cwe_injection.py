"""Injection Vulnerability Detectors - 25+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class SQLInjectionDetector(VulnerabilityDetector):
    """CWE-89: SQL Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'cursor\.execute\(["\'][^"\']*\+', "CWE-89", "critical"),
            (r'db\.query\(["\'][^"\']*\+', "CWE-89", "critical"),
            (r'executeQuery\(["\'][^"\']*\+', "CWE-89", "critical"),
            (r'rawQuery\(["\'][^"\']*\+', "CWE-89", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'prepared|bind|param|escape', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="SQL Injection",
                            description="SQL injection vulnerability. Use parameterized queries.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class LDAPInjectionDetector(VulnerabilityDetector):
    """CWE-90: LDAP Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'ldap\.search\(["\'][^"\']*\+', "CWE-90", "high"),
            (r'dirContext\.search\(["\'][^"\']*\+', "CWE-90", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|filter', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="LDAP Injection",
                            description="LDAP injection vulnerability. Use proper escaping or filtering.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class CommandInjectionDetector(VulnerabilityDetector):
    """CWE-78: Command Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'subprocess\.(call|Popen|run)\(["\'][^"\']*\+', "CWE-78", "critical"),
            (r'os\.system\(["\'][^"\']*\+', "CWE-78", "critical"),
            (r'os\.popen\(["\'][^"\']*\+', "CWE-78", "critical"),
            (r'exec\(["\'][^"\']*\+', "CWE-78", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'shlex\.quote|shell.*False', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Command Injection",
                            description="Command injection vulnerability. Use shell=False or proper escaping.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class XMLInjectionDetector(VulnerabilityDetector):
    """CWE-91: XML Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'xml\.etree\.ElementTree.*\+', "CWE-91", "high"),
            (r'xml\.dom\.minidom.*\+', "CWE-91", "high"),
            (r'xml\.sax.*\+', "CWE-91", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote|xml_escape', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="XML Injection",
                            description="XML injection vulnerability. Use proper XML escaping.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class CodeInjectionDetector(VulnerabilityDetector):
    """CWE-94: Code Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'eval\(["\'][^"\']*\+', "CWE-94", "critical"),
            (r'exec\(["\'][^"\']*\+', "CWE-94", "critical"),
            (r'compile\(["\'][^"\']*\+', "CWE-94", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Code Injection",
                        description="Code injection vulnerability. Never execute user-controlled code.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

class XPathInjectionDetector(VulnerabilityDetector):
    """CWE-643: XPath Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'xpath\(["\'][^"\']*\+', "CWE-643", "high"),
            (r'evaluate\(["\'][^"\']*\+', "CWE-643", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="XPath Injection",
                            description="XPath injection vulnerability. Use proper escaping.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class XQueryInjectionDetector(VulnerabilityDetector):
    """CWE-652: XQuery Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'xquery\(["\'][^"\']*\+', "CWE-652", "high"),
            (r'XQuery.*\+', "CWE-652", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="XQuery Injection",
                        description="XQuery injection vulnerability. Use parameterized queries.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="injection"
                    ))
        return vulnerabilities

class ELInjectionDetector(VulnerabilityDetector):
    """CWE-917: Expression Language Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\$\{.*param\[.*\]\}', "CWE-917", "high"),
            (r'\#\{.*param\[.*\]\}', "CWE-917", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Expression Language Injection",
                        description="EL injection vulnerability. Validate and escape user input.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

class HTTPResponseSplittingDetector(VulnerabilityDetector):
    """CWE-113: HTTP Response Splitting"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'setHeader\(["\'][^"\']*\+', "CWE-113", "high"),
            (r'addHeader\(["\'][^"\']*\+', "CWE-113", "high"),
            (r'response\.setHeader.*\+', "CWE-113", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'encode|escape', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="HTTP Response Splitting",
                            description="HTTP response splitting vulnerability. Validate header values.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class CRLFInjectionDetector(VulnerabilityDetector):
    """CWE-93: CRLF Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'print\(["\'][^"\']*\\r\\n', "CWE-93", "medium"),
            (r'write\(["\'][^"\']*\\r\\n', "CWE-93", "medium"),
            (r'\n\r|\r\n', "CWE-93", "low"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'header|cookie|log', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="CRLF Injection",
                            description="CRLF injection vulnerability. Sanitize input containing CRLF.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class IMAPInjectionDetector(VulnerabilityDetector):
    """CWE-147: IMAP/SMTP Command Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'imap\..*\+', "CWE-147", "high"),
            (r'smtp\..*\+', "CWE-147", "high"),
            (r'pop3\..*\+', "CWE-147", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="IMAP/SMTP Injection",
                        description="Mail protocol injection vulnerability. Validate commands.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="injection"
                    ))
        return vulnerabilities

class NoSQLInjectionDetector(VulnerabilityDetector):
    """CWE-943: NoSQL Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'db\.collection\.find\(["\'][^"\']*\+', "CWE-943", "high"),
            (r'mongo.*find\(["\'][^"\']*\+', "CWE-943", "high"),
            (r'findOne\(["\'][^"\']*\+', "CWE-943", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|ObjectId', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="NoSQL Injection",
                            description="NoSQL injection vulnerability. Use proper query sanitization.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class HibernateInjectionDetector(VulnerabilityDetector):
    """CWE-564: Hibernate Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'createQuery\(["\'][^"\']*\+', "CWE-564", "high"),
            (r'createSQLQuery\(["\'][^"\']*\+', "CWE-564", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'setParameter|named', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Hibernate Injection",
                            description="Hibernate injection vulnerability. Use parameterized queries.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class FormatStringInjectionDetector(VulnerabilityDetector):
    """CWE-134: Use of Externally-Controlled Format String"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'printf\([^,]*\+', "CWE-134", "high"),
            (r'sprintf\([^,]*\+', "CWE-134", "high"),
            (r'fprintf\([^,]*\+', "CWE-134", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Format String Injection",
                        description="Format string vulnerability. Never use user input as format string.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

# Additional injection detectors for the remaining CWEs
class SSIInjectionDetector(VulnerabilityDetector):
    """CWE-97: Server-Side Include Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'<!--#include.*\+', "CWE-97", "critical"),
            (r'<!--#exec.*\+', "CWE-97", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="SSI Injection",
                        description="Server-side include injection. Validate include paths.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

class TemplateInjectionDetector(VulnerabilityDetector):
    """CWE-74: Template Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'render_template.*\+', "CWE-74", "high"),
            (r'jinja2.*\+', "CWE-74", "high"),
            (r'mustache.*\+', "CWE-74", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|sanitize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Template Injection",
                            description="Template injection vulnerability. Sanitize template input.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class ShellInjectionDetector(VulnerabilityDetector):
    """CWE-75: Shell Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'shell_exec\(["\'][^"\']*\+', "CWE-75", "critical"),
            (r'`.*\+.*`', "CWE-75", "critical"),
            (r'backticks.*\+', "CWE-75", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Shell Injection",
                        description="Shell injection vulnerability. Use proper escaping or avoid shell execution.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="injection"
                    ))
        return vulnerabilities

class OSCommandInjectionDetector(VulnerabilityDetector):
    """CWE-83: OS Command Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Runtime\.getRuntime\(\)\.exec\(["\'][^"\']*\+', "CWE-83", "critical"),
            (r'ProcessBuilder.*\+', "CWE-83", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|quote', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="OS Command Injection",
                            description="OS command injection vulnerability. Validate and escape command arguments.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="high", category="injection"
                        ))
        return vulnerabilities

class HTMLInjectionDetector(VulnerabilityDetector):
    """CWE-87: HTML Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'innerHTML.*\+', "CWE-87", "medium"),
            (r'document\.write.*\+', "CWE-87", "medium"),
            (r'\.html\(.*\+', "CWE-87", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|encode|sanitize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="HTML Injection",
                            description="HTML injection vulnerability. Use proper HTML encoding.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

class ResourceInjectionDetector(VulnerabilityDetector):
    """CWE-146: Resource Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'open\(["\'][^"\']*\+', "CWE-146", "high"),
            (r'file_get_contents\(["\'][^"\']*\+', "CWE-146", "high"),
            (r'readFile\(["\'][^"\']*\+', "CWE-146", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'user|input|param', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Resource Injection",
                            description="Resource injection vulnerability. Validate file paths.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities

def get_injection_detectors():
    """Get all injection detectors"""
    return [
        SQLInjectionDetector(),
        LDAPInjectionDetector(),
        CommandInjectionDetector(),
        XMLInjectionDetector(),
        CodeInjectionDetector(),
        XPathInjectionDetector(),
        XQueryInjectionDetector(),
        ELInjectionDetector(),
        HTTPResponseSplittingDetector(),
        CRLFInjectionDetector(),
        IMAPInjectionDetector(),
        NoSQLInjectionDetector(),
        HibernateInjectionDetector(),
        FormatStringInjectionDetector(),
        SSIInjectionDetector(),
        TemplateInjectionDetector(),
        ShellInjectionDetector(),
        OSCommandInjectionDetector(),
        HTMLInjectionDetector(),
        ResourceInjectionDetector(),

        # Additional Injection Detectors
        DataQueryLogicInjectionDetector(),
        XQueryInjectionDetector(),
        ExpressionLanguageInjectionDetector(),
    ]

class DataQueryLogicInjectionDetector(VulnerabilityDetector):
    """CWE-943: Improper Neutralization of Special Elements in Data Query Logic"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'\.find\([^)]*\$', "CWE-943", "high"),  # MongoDB/NoSQL injection
            (r'collection\.find\([^)]*\+', "CWE-943", "high"),
            (r'\$where\s*:\s*[^}]*\+', "CWE-943", "high"),  # MongoDB $where injection
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'sanitize|escape|bind|param', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Data Query Logic Injection",
                            description="Potential injection in data query logic. Use parameterized queries.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities


class XQueryInjectionDetector(VulnerabilityDetector):
    """CWE-652: Improper Neutralization of Data within XQuery Expressions"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'xquery\.execute\([^)]*\+', "CWE-652", "high"),
            (r'doc\([^)]*\+', "CWE-652", "high"),  # XQuery document function
            (r'collection\([^)]*\+', "CWE-652", "high"),  # XQuery collection function
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'sanitize|escape|quote', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="XQuery Injection",
                            description="Potential XQuery injection. Use proper escaping or parameterized queries.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities


class ExpressionLanguageInjectionDetector(VulnerabilityDetector):
    """CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'el\.evaluate\([^)]*\+', "CWE-917", "high"),  # Java EL injection
            (r'ExpressionFactory\.createValueExpression\([^)]*\+', "CWE-917", "high"),
            (r'\$\{[^}]*\$\{', "CWE-917", "high"),  # Nested EL expressions
            (r'#\{[^}]*#\{', "CWE-917", "high"),  # JSF EL injection
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'escape|encode|sanitize', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Expression Language Injection",
                            description="Potential expression language injection. Validate and sanitize input.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="injection"
                        ))
        return vulnerabilities
