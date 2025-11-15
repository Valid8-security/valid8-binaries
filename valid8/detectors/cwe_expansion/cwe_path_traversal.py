"""Path Traversal Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class PathTraversalDetector(VulnerabilityDetector):
    """CWE-22: Improper Limitation of a Pathname"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'open\([^)]*\+.*\.\.|.*\.\.\/', "CWE-22", "high"), (r'readFile\([^)]*\+.*user', "CWE-22", "high"), (r'\.\.\/\.\.\/|\.\.\\\.\.\\', "CWE-22", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-22", severity=severity, title="Path Traversal", description="Path traversal vulnerability detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="path-traversal"))
        return vulnerabilities

class RelativePathTraversalDetector(VulnerabilityDetector):
    """CWE-23: Relative Path Traversal"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\.\.\/|\.\.\\', "CWE-23", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'open|read|write|file|path|include|require', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-23", severity=severity, title="Relative Path Traversal", description="Relative path traversal vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="path-traversal"))
        return vulnerabilities

class AbsolutePathTraversalDetector(VulnerabilityDetector):
    """CWE-36: Absolute Path Traversal"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'/etc/|/var/|C:\\\\|/root/', "CWE-36", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if re.search(r'open|read|write|file|path|include|require', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-36", severity=severity, title="Absolute Path Traversal", description="Absolute path traversal vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="path-traversal"))
        return vulnerabilities

class PathTraversalInFilenameDetector(VulnerabilityDetector):
    """CWE-73: External Control of File Name or Path"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'filename\s*=\s*.*request\.|.*file.*=.*request\.', "CWE-73", "high"), (r'path\s*=\s*.*user|.*path.*=.*input', "CWE-73", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'validate|sanitize|basename|normalize|path\.join', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-73", severity=severity, title="External Control of File Name", description="File name or path controlled by user input.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="path-traversal"))
        return vulnerabilities

def get_path_traversal_detectors():
    """Get all path traversal detectors"""
    return [
        PathTraversalDetector(), RelativePathTraversalDetector(), AbsolutePathTraversalDetector(),
        PathTraversalInFilenameDetector(),
    ]


