"""CWE Top 25 Most Dangerous Software Weaknesses (2024)"""
import re
from pathlib import Path
from typing import List
from parry.scanner import Vulnerability, VulnerabilityDetector

class OutOfBoundsWriteDetector(VulnerabilityDetector):
    """CWE-787: Out-of-bounds Write"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\bstrcpy\s*\(', "CWE-787", "critical"), (r'\bstrcat\s*\(', "CWE-787", "critical"), (r'\bsprintf\s*\(', "CWE-787", "critical"), (r'\bgets\s*\(', "CWE-787", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Out-of-bounds Write", description="Potential out-of-bounds write detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="memory-safety"))
        return vulnerabilities

class OutOfBoundsReadDetector(VulnerabilityDetector):
    """CWE-125: Out-of-bounds Read"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\bstrcpy\s*\([^)]*,\s*\w+\[', "CWE-125", "high"), (r'\w+\s*\[\s*\w+\s*\+\s*\w+\s*\]', "CWE-125", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'(if|assert|check).*(<|<=|>|>=|length|size|bounds)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Out-of-bounds Read", description="Potential out-of-bounds read detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class ImproperNeutralizationDetector(VulnerabilityDetector):
    """CWE-77: Improper Neutralization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'exec\([^)]*\+.*user|.*\+.*input', "CWE-77", "critical"), (r'system\([^)]*\+.*user', "CWE-77", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'escape|sanitize|quote|encode|validate', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Improper Neutralization", description="Command injection vulnerability.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="injection"))
        return vulnerabilities

class CSRFDetector(VulnerabilityDetector):
    """CWE-352: Cross-Site Request Forgery"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'@app\.(route|post|put|delete)\([^)]*\)\s*\n(?!.*@(csrf|csrf_exempt))', "CWE-352", "high"), (r'csrf\.enabled\s*=\s*False', "CWE-352", "high")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-352", severity=severity, title="Cross-Site Request Forgery", description="CSRF protection missing or disabled.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="csrf"))
        return vulnerabilities

class UnrestrictedUploadDetector(VulnerabilityDetector):
    """CWE-434: Unrestricted Upload of File"""
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

class NullPointerDereferenceDetector(VulnerabilityDetector):
    """CWE-476: NULL Pointer Dereference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'->.*\(|\.\w+\(.*\)\s*\n(?!.*if.*!=.*null)', "CWE-476", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'(if|assert|guard|check).*(null|None)', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="NULL Pointer Dereference", description="Potential NULL pointer dereference.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class IntegerOverflowDetector(VulnerabilityDetector):
    """CWE-190: Integer Overflow"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'\w+\s*\*\s*\w+|.*\s*\+\s*\w+.*\[', "CWE-190", "low"), (r'malloc\([^)]*\*\s*\w+', "CWE-190", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'check|validate|overflow|safe', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Integer Overflow", description="Potential integer overflow detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class MissingEncryptionDetector(VulnerabilityDetector):
    """CWE-311: Missing Encryption"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'password\s*=\s*["\'][^"\']+["\']', "CWE-311", "critical"), (r'http://[^s]', "CWE-311", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not re.search(r'encrypt|hash|bcrypt|tls|ssl|https', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Missing Encryption", description="Sensitive data not encrypted.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="encryption"))
        return vulnerabilities

class InsecureStorageDetector(VulnerabilityDetector):
    """CWE-922: Insecure Storage"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'localStorage\.(setItem|set)\([^)]*password', "CWE-922", "high"), (r'sessionStorage\.(setItem|set)\([^)]*token', "CWE-922", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe=cwe, severity=severity, title="Insecure Storage", description="Sensitive data stored insecurely.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="storage"))
        return vulnerabilities

class HardcodedCredentialsDetector(VulnerabilityDetector):
    """CWE-798: Hardcoded Credentials"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'password\s*=\s*["\'][^"\']{3,}["\']', "CWE-798", "critical"), (r'API_KEY\s*=\s*["\'][^"\']+["\']', "CWE-798", "critical")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if not re.search(r'#.*test|#.*example|#.*demo', line, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-798", severity=severity, title="Hardcoded Credentials", description="Hardcoded credentials detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="secrets"))
        return vulnerabilities

class UnsafeDeserializationDetector(VulnerabilityDetector):
    """CWE-502: Unsafe Deserialization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'pickle\.loads\(|.*unpickle\(|.*ObjectInputStream', "CWE-502", "critical"), (r'JSON\.parse\(.*request\.(body|params)', "CWE-502", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-502", severity=severity, title="Unsafe Deserialization", description="Unsafe deserialization detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="deserialization"))
        return vulnerabilities

class PathTraversalDetector(VulnerabilityDetector):
    """CWE-22: Path Traversal"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'open\([^)]*\+.*\.\.|.*\.\.\/', "CWE-22", "high"), (r'readFile\([^)]*\+.*user', "CWE-22", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-22", severity=severity, title="Path Traversal", description="Path traversal vulnerability detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="path-traversal"))
        return vulnerabilities

class SSRFDetector(VulnerabilityDetector):
    """CWE-918: Server-Side Request Forgery"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'requests\.get\(.*\+.*request', "CWE-918", "high"), (r'fetch\(.*\+.*user', "CWE-918", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-918", severity=severity, title="Server-Side Request Forgery", description="SSRF vulnerability detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="api-security"))
        return vulnerabilities

class XXEDetector(VulnerabilityDetector):
    """CWE-611: XML External Entity"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'XMLParser.*resolve_entities|.*DOCTYPE.*ENTITY', "CWE-611", "high"), (r'\.parse\(.*resolve_entities\s*=\s*True', "CWE-611", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-611", severity=severity, title="XML External Entity", description="XXE vulnerability detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="xml"))
        return vulnerabilities

class WeakCryptoDetector(VulnerabilityDetector):
    """CWE-327: Weak Cryptographic Hash"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'md5\(|sha1\(|hashlib\.(md5|sha1)', "CWE-327", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-327", severity=severity, title="Weak Cryptographic Hash", description="Weak hash algorithm detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="high", category="cryptography"))
        return vulnerabilities

class UseAfterFreeDetector(VulnerabilityDetector):
    """CWE-416: Use After Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'free\(.*\)|.*delete\s+.*;', "CWE-416", "high")]
        for i, line in enumerate(lines, 1):
            context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
            for pattern, cwe, severity in patterns:
                if re.search(pattern, context, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-416", severity=severity, title="Use After Free", description="Potential use after free.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
        return vulnerabilities

class DoubleFreeDetector(VulnerabilityDetector):
    """CWE-415: Double Free"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        var_pattern = r'(free|delete)\s*\(?\s*(\w+)\s*\)?'
        vars_freed = {}
        for i, line in enumerate(lines, 1):
            match = re.search(var_pattern, line, re.IGNORECASE)
            if match:
                var = match.group(2)
                if var in vars_freed:
                    vulnerabilities.append(Vulnerability(cwe="CWE-415", severity="high", title="Double Free", description=f"Potential double free of '{var}'.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="memory-safety"))
                vars_freed[var] = i
        return vulnerabilities

class ImproperInputValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'request\.(body|params|query)\[.*\]\s*(?!.*validate)', "CWE-20", "medium")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                    if not re.search(r'validate|sanitize|check|filter', context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(cwe="CWE-20", severity=severity, title="Improper Input Validation", description="User input used without validation.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="input-validation"))
        return vulnerabilities

def get_top25_detectors():
    """Get all CWE Top 25 detectors"""
    return [
        OutOfBoundsWriteDetector(), OutOfBoundsReadDetector(), ImproperNeutralizationDetector(),
        CSRFDetector(), UnrestrictedUploadDetector(), NullPointerDereferenceDetector(),
        IntegerOverflowDetector(), MissingEncryptionDetector(), InsecureStorageDetector(),
        HardcodedCredentialsDetector(), UnsafeDeserializationDetector(), PathTraversalDetector(),
        SSRFDetector(), XXEDetector(), WeakCryptoDetector(), UseAfterFreeDetector(),
        DoubleFreeDetector(), ImproperInputValidationDetector(),
    ]
