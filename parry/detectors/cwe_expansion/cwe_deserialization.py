"""Deserialization Vulnerability Detectors - 5+ CWEs"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class UnsafeDeserializationDetector(VulnerabilityDetector):
    """CWE-502: Unsafe Deserialization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'pickle\.loads\(|.*unpickle\(', "CWE-502", "critical"), (r'ObjectInputStream|.*readObject\(', "CWE-502", "critical"), (r'yaml\.load\(|.*YAML\.load\(', "CWE-502", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-502", severity=severity, title="Unsafe Deserialization", description="Unsafe deserialization detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="deserialization"))
        return vulnerabilities

class InsecureDeserializationDetector(VulnerabilityDetector):
    """CWE-502: Insecure Deserialization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'JSON\.parse\(.*request\.(body|params)', "CWE-502", "high"), (r'eval\(.*JSON\.parse', "CWE-502", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-502", severity=severity, title="Insecure Deserialization", description="Insecure deserialization detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="deserialization"))
        return vulnerabilities

class DeserializationOfUntrustedDataDetector(VulnerabilityDetector):
    """CWE-502: Deserialization of Untrusted Data"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\.loads\([^)]*request\.|.*\.loads\([^)]*user', "CWE-502", "critical"), (r'deserialize\([^)]*input|.*\.deserialize\([^)]*request', "CWE-502", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-502", severity=severity, title="Deserialization of Untrusted Data", description="Deserialization of untrusted data detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="deserialization"))
        return vulnerabilities

def get_deserialization_detectors():
    """Get all deserialization detectors"""
    return [
        UnsafeDeserializationDetector(), InsecureDeserializationDetector(), DeserializationOfUntrustedDataDetector(),
    ]

