"""Code Quality Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class CodeInjectionDetector(VulnerabilityDetector):
    """CWE-94: Code Injection"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'eval\([^)]*\+.*user|.*\+.*input', "CWE-94", "critical"), (r'eval\s*\(\s*\$\{', "CWE-94", "critical"), (r'Function\([^)]*\+.*user', "CWE-94", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-94", severity=severity, title="Code Injection", description="Code injection vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="injection"))
        return vulnerabilities

class ImproperControlOfGenerationOfCodeDetector(VulnerabilityDetector):
    """CWE-95: Improper Control of Generation of Code"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'eval\(.*request\.|.*eval\(.*user', "CWE-95", "critical"), (r'compile\([^)]*\+.*user', "CWE-95", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-95", severity=severity, title="Improper Control of Code Generation", description="Code generation controlled by user input.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="code-quality"))
        return vulnerabilities

class ImproperNeutralizationOfDirectivesDetector(VulnerabilityDetector):
    """CWE-96: Improper Neutralization of Directives"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'include\([^)]*\+.*user|.*require\([^)]*\+.*input', "CWE-96", "critical"), (r'include.*\$|.*require.*\$', "CWE-96", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-96", severity=severity, title="Improper Neutralization of Directives", description="Directives not properly neutralized.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="code-quality"))
        return vulnerabilities

class ImproperControlOfFilenameForIncludeDetector(VulnerabilityDetector):
    """CWE-98: Improper Control of Filename for Include/Require"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'include\([^)]*\+.*request|.*require\([^)]*\+.*user', "CWE-98", "critical"), (r'include.*\$|.*require.*\$', "CWE-98", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-98", severity=severity, title="Improper Control of Filename", description="Filename for include/require controlled by user.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="code-quality"))
        return vulnerabilities

def get_code_quality_detectors():
    """Get all code quality detectors"""
    return [
        CodeInjectionDetector(), ImproperControlOfGenerationOfCodeDetector(),
        ImproperNeutralizationOfDirectivesDetector(), ImproperControlOfFilenameForIncludeDetector(),
    ]


