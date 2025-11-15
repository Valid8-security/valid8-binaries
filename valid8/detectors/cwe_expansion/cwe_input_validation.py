"""Input Validation Vulnerability Detectors - 15+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class ImproperInputValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'request\.(body|params|query)\[.*\]\s*(?!.*validate|.*sanitize)', "CWE-20", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'validate|sanitize|check|filter', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-20", severity=severity, title="Improper Input Validation", description="User input used without validation.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="input-validation"))
        return vulnerabilities

class UncontrolledFormatStringDetector(VulnerabilityDetector):
    """CWE-134: Use of Externally-Controlled Format String"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'printf\([^)]*\+.*user|.*\+.*input', "CWE-134", "high"), (r'sprintf\([^)]*\+.*user', "CWE-134", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-134", severity=severity, title="Format String Vulnerability", description="Format string vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="input-validation"))
        return vulnerabilities

class ImproperRestrictionOfOperationsDetector(VulnerabilityDetector):
    """CWE-840: Business Logic Errors"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'price\s*=\s*.*request\.|.*amount\s*=\s*.*request\.', "CWE-840", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-840", severity=severity, title="Business Logic Error", description="Business-critical values controlled by user input.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="business-logic"))
        return vulnerabilities

class OSCommandInjectionDetector(VulnerabilityDetector):
    """CWE-78: OS Command Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'exec\([^)]*\+.*user|.*\+.*input', "CWE-78", "critical"), (r'system\([^)]*\+.*user', "CWE-78", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-78", severity=severity, title="OS Command Injection", description="Command injection vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="injection"))
        return vulnerabilities

class FailureToSanitizeDetector(VulnerabilityDetector):
    """CWE-75: Failure to Sanitize Special Elements"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'output.*=.*input.*\n(?!.*sanitize|.*escape|.*encode)', "CWE-75", "medium")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-75", severity=severity, title="Failure to Sanitize", description="Failure to sanitize special elements.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="input-validation"))
        return vulnerabilities

class ImproperNeutralizationDetector(VulnerabilityDetector):
    """CWE-77: Improper Neutralization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'exec\([^)]*\+.*user|.*\+.*input', "CWE-77", "critical"), (r'system\([^)]*\+.*input', "CWE-77", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'escape|sanitize|quote|encode', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Improper Neutralization", description="Improper neutralization vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="input-validation"))
        return vulnerabilities

class ImproperNeutralizationOfSpecialElementsDetector(VulnerabilityDetector):
    """CWE-74: Improper Neutralization of Special Elements"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'eval\([^)]*\+.*user', "CWE-74", "critical"), (r'exec\([^)]*\+.*input', "CWE-74", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'escape|sanitize|quote|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-74", severity=severity, title="Improper Neutralization", description="Improper neutralization of special elements.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="input-validation"))
        return vulnerabilities

class ImproperNeutralizationOfSpecialElementsInOutputDetector(VulnerabilityDetector):
    """CWE-79: Improper Neutralization of Input During Web Page Generation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'innerHTML\s*=\s*.*\+.*user|.*\+.*input', "CWE-79", "high"), (r'document\.write\s*\([^)]*\+.*request', "CWE-79", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-79", severity=severity, title="XSS via Improper Neutralization", description="Improper neutralization in web output.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="xss"))
        return vulnerabilities

def get_input_validation_detectors():
    """Get all input validation detectors"""
    return [
        ImproperInputValidationDetector(), UncontrolledFormatStringDetector(),
        ImproperRestrictionOfOperationsDetector(), OSCommandInjectionDetector(),
        FailureToSanitizeDetector(), ImproperNeutralizationDetector(),
        ImproperNeutralizationOfSpecialElementsDetector(), ImproperNeutralizationOfSpecialElementsInOutputDetector(),
    ]
