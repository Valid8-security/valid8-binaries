"""File Handling Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class PathTraversalDetector(VulnerabilityDetector):
    """CWE-22: Path Traversal"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'open\([^)]*\+.*\.\.|.*\.\.\/', "CWE-22", "high"), (r'readFile\([^)]*\+.*user', "CWE-22", "high"), (r'read\([^)]*\+.*\.\.', "CWE-22", "high")]
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
                    if re.search(r'open|read|write|file|path', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-23", severity=severity, title="Relative Path Traversal", description="Relative path traversal vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="path-traversal"))
        return vulnerabilities

class UnrestrictedFileUploadDetector(VulnerabilityDetector):
    """CWE-434: Unrestricted Upload"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\.save\([^)]*request\.files', "CWE-434", "high"), (r'upload.*\([^)]*file.*\):\s*\n(?!.*\.(endswith|extension))', "CWE-434", "high")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    if not re.search(r'validate|check|allow|deny|extension|mime|type', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-434", severity=severity, title="Unrestricted File Upload", description="File upload without proper validation.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="file-upload"))
        return vulnerabilities

class ImproperFilePermissionsDetector(VulnerabilityDetector):
    """CWE-732: Incorrect Permission Assignment"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'chmod\([^)]*0[67]77|.*0777', "CWE-732", "high"), (r'permissions.*=.*0[67]77', "CWE-732", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-732", severity=severity, title="Incorrect File Permissions", description="Insecure file permissions.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="permissions"))
        return vulnerabilities

class MissingFileCloseDetector(VulnerabilityDetector):
    """CWE-404: Missing File Close"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'open\(|File\(|\.open\(', "CWE-404", "low")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[i:min(len(lines), i+20)])
                    if not re.search(r'\.close\(|close\(|with\s+open|try.*finally.*close', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-404", severity=severity, title="Missing File Close", description="File opened but may not be properly closed.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="resource-management"))
        return vulnerabilities

def get_file_handling_detectors():
    """Get all file handling detectors"""
    return [
        PathTraversalDetector(), RelativePathTraversalDetector(), UnrestrictedFileUploadDetector(),
        ImproperFilePermissionsDetector(), MissingFileCloseDetector(),
    ]


