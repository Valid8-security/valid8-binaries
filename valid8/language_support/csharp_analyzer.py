"""C# language security analyzer."""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors
from ..codeql_analyzer import DataFlowAnalyzer


@dataclass(frozen=True)
class PatternRule:
    """Represents a reusable pattern-based detection rule."""

    name: str
    cwe: str
    severity: str
    title: str
    description: str
    patterns: List[str]
    evidence: Optional[List[str]] = None
    confidence: float = 0.8
    advanced: bool = False


def _compile(patterns: Iterable[str]) -> List[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


PATTERN_RULES: Dict[str, PatternRule] = {
    "detect_command_injection": PatternRule(
        name="detect_command_injection",
        cwe="CWE-78",
        severity="critical",
        title="OS Command Injection",
        description="User-controlled input flows into operating system command execution.",
        patterns=[
            r"Process\.Start\s*\(",
            r"ProcessStartInfo\s*\(",
            r"cmd\.exe",
            r"powershell\.exe",
            r"bash",
        ],
        evidence=["Request", "QueryString", "Form", "Input"],
        confidence=0.9,
    ),
    "detect_code_injection": PatternRule(
        name="detect_code_injection",
        cwe="CWE-94",
        severity="critical",
        title="Code Injection",
        description="Invocation of dynamic code execution primitives.",
        patterns=[
            r"Eval\s*\(",
            r"Execute\s*\(",
            r"Compiler\.CompileAssemblyFromSource",
            r"CSScript\.Evaluator",
        ],
        evidence=["Request", "QueryString", "Form"],
        confidence=0.9,
    ),
    "detect_sql_injection": PatternRule(
        name="detect_sql_injection",
        cwe="CWE-89",
        severity="critical",
        title="SQL Injection",
        description="Database query constructed with unsanitised user input.",
        patterns=[
            r"ExecuteNonQuery\s*\(",
            r"ExecuteReader\s*\(",
            r"ExecuteScalar\s*\(",
            r"SqlCommand\s*\(",
        ],
        evidence=["Request", "QueryString", "Form", "+", "string.Format"],
        confidence=0.85,
    ),
    "detect_xss": PatternRule(
        name="detect_xss",
        cwe="CWE-79",
        severity="high",
        title="Cross-Site Scripting",
        description="HTML response built directly from user-controlled data.",
        patterns=[
            r"Response\.Write\s*\(",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"document\.write\s*\(",
        ],
        evidence=["Request", "QueryString", "Form"],
        confidence=0.8,
    ),
    "detect_path_traversal": PatternRule(
        name="detect_path_traversal",
        cwe="CWE-22",
        severity="high",
        title="Path Traversal",
        description="File system access constructed with user input.",
        patterns=[
            r"File\.ReadAllText",
            r"File\.WriteAllText",
            r"File\.OpenRead",
            r"Path\.Combine",
            r"Directory\.GetFiles",
        ],
        evidence=["..\\", "../", "Request", "QueryString", "Form"],
        confidence=0.8,
    ),
    "detect_weak_crypto": PatternRule(
        name="detect_weak_crypto",
        cwe="CWE-327",
        severity="medium",
        title="Weak Cryptography",
        description="Use of weak or insecure cryptographic primitives.",
        patterns=[
            r"MD5\s",
            r"SHA1\s",
            r"DES\s",
            r"RC4\s",
        ],
        confidence=0.75,
    ),
    "detect_hardcoded_secrets": PatternRule(
        name="detect_hardcoded_secrets",
        cwe="CWE-798",
        severity="critical",
        title="Hardcoded Secret",
        description="Sensitive token or credential embedded directly in source code.",
        patterns=[
            r"(?i)(api|secret|token|key)[\w\-]*\s*[:=]\s*[\"\'][A-Za-z0-9/+=]{8,}[\"']",
        ],
        confidence=0.9,
    ),
    "detect_insecure_deserialization": PatternRule(
        name="detect_insecure_deserialization",
        cwe="CWE-502",
        severity="critical",
        title="Unsafe Deserialization",
        description="Use of unsafe deserialization routines with untrusted data.",
        patterns=[
            r"BinaryFormatter\.Deserialize",
            r"JsonConvert\.DeserializeObject",
            r"XmlSerializer\.Deserialize",
        ],
        evidence=["Request", "QueryString", "Form"],
        confidence=0.85,
    ),
    "detect_ssrf": PatternRule(
        name="detect_ssrf",
        cwe="CWE-918",
        severity="critical",
        title="Server-Side Request Forgery",
        description="HTTP client request built from user input.",
        patterns=[
            r"HttpClient\.GetAsync",
            r"WebClient\.DownloadString",
            r"HttpWebRequest\.Create",
            r"WebRequest\.Create",
        ],
        evidence=["Request", "QueryString", "Form"],
        confidence=0.85,
        advanced=True,
    ),
    "detect_open_redirect": PatternRule(
        name="detect_open_redirect",
        cwe="CWE-601",
        severity="medium",
        title="Open Redirect",
        description="Redirect destination derived from user input without validation.",
        patterns=[
            r"Response\.Redirect\s*\(",
        ],
        evidence=["Request", "QueryString", "Form"],
        confidence=0.7,
    ),
    "detect_information_disclosure": PatternRule(
        name="detect_information_disclosure",
        cwe="CWE-200",
        severity="medium",
        title="Information Disclosure",
        description="Sensitive information exposed through logging or responses.",
        patterns=[
            r"Console\.WriteLine.*(password|secret|token)",
            r"Debug\.WriteLine.*(password|secret|token)",
            r"Response\.Write.*(password|secret|token)",
        ],
        confidence=0.7,
        advanced=True,
    ),
}

ADVANCED_RULE_NAMES = {name for name, rule in PATTERN_RULES.items() if rule.advanced}


class CSharpAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for C# source files."""

    ANALYZE_ORDER = [
        "detect_command_injection",
        "detect_code_injection",
        "detect_sql_injection",
        "detect_xss",
        "detect_path_traversal",
        "detect_weak_crypto",
        "detect_hardcoded_secrets",
        "detect_insecure_deserialization",
        "detect_ssrf",
        "detect_open_redirect",
        "detect_information_disclosure",
    ]

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.advanced_hit_counter: Counter[str] = Counter()

    def get_supported_cwes(self) -> List[str]:
        return [
            "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94",
            "CWE-95", "CWE-200", "CWE-287", "CWE-327", "CWE-352", "CWE-502",
            "CWE-601", "CWE-611", "CWE-798", "CWE-918",
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        self.logger.debug("Starting C# analysis", extra={"filepath": filepath})
        self.file_path = filepath
        self.advanced_hit_counter = Counter()
        vulnerabilities: List[Vulnerability] = []

        for detector_name in self.ANALYZE_ORDER:
            detector = getattr(self, detector_name, None)
            if not callable(detector):
                continue
            try:
                findings = detector(code, filepath)
                vulnerabilities.extend(findings)
            except Exception as exc:
                self.logger.debug("Detector %s failed: %s", detector_name, exc)

        vulnerabilities.extend(self._detect_critical_credentials(code, filepath))

        # Universal, language-agnostic detectors
        universal_detectors = [
            self.detect_improper_input_validation,
            self.detect_information_exposure,
            self.detect_improper_authentication,
            self.detect_csrf,
            self.detect_graphql_security,
            self.detect_jwt_security,
            self.detect_redos,
            self.detect_incorrect_permissions,
        ]

        for detector in universal_detectors:
            try:
                vulnerabilities.extend(detector(code, filepath))
            except Exception as exc:
                self.logger.debug("Universal detector %s failed: %s", detector.__name__, exc)

        # Data flow analysis (best-effort)
        try:
            data_flow_vulns = self.data_flow_analyzer.analyze(code, filepath)
            vulnerabilities.extend(data_flow_vulns)
        except Exception as exc:
            self.logger.debug("Data flow analysis failed: %s", exc)

        return self._deduplicate(vulnerabilities)

    def get_advanced_detector_stats(self) -> Dict[str, int]:
        return dict(self.advanced_hit_counter)

    # Individual detector implementations
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_command_injection", code, filepath)

    def detect_code_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_code_injection", code, filepath)

    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_sql_injection", code, filepath)

    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_xss", code, filepath)

    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_path_traversal", code, filepath)

    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_weak_crypto", code, filepath)

    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_hardcoded_secrets", code, filepath)

    def detect_insecure_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_deserialization", code, filepath)

    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_ssrf", code, filepath)

    def detect_open_redirect(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_open_redirect", code, filepath)

    def detect_information_disclosure(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_information_disclosure", code, filepath)

    def _run_rule(self, rule_name: str, code: str, filepath: str) -> List[Vulnerability]:
        rule = PATTERN_RULES.get(rule_name)
        if not rule:
            return []

        compiled = _compile(rule.patterns)
        lines = code.splitlines()
        findings: List[Vulnerability] = []

        for idx, line in enumerate(lines, start=1):
            if self._is_comment(line):
                continue

            if not any(pattern.search(line) for pattern in compiled):
                continue

            if rule.evidence and not any(token in line for token in rule.evidence):
                continue

            vuln = self._create_vulnerability(
                cwe=rule.cwe,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                code=code,
                filepath=filepath,
                line_number=idx,
                confidence=f"{rule.confidence:.2f}",
            )
            findings.append(vuln)

            if rule.name in ADVANCED_RULE_NAMES:
                self._register_advanced_hit(rule.name, idx)

        return findings

    def _detect_critical_credentials(self, code: str, filepath: str) -> List[Vulnerability]:
        patterns = [
            re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*[:=]\s*[\"\'][A-Za-z0-9/+=]{20,}[\"']"),
            re.compile(r"(?i)AWS_ACCESS_KEY_ID\s*[:=]\s*[\"\'][A-Z0-9]{16,}[\"']"),
            re.compile(r"(?i)(PRIVATE|PUBLIC)_KEY\s*[:=]\s*[\"\'][^-\n]{24,}[\"']"),
        ]

        findings: List[Vulnerability] = []
        for idx, line in enumerate(code.splitlines(), start=1):
            if self._is_comment(line):
                continue
            if any(pattern.search(line) for pattern in patterns):
                findings.append(self._create_vulnerability(
                    cwe="CWE-798",
                    severity="critical",
                    title="Hardcoded Credential",
                    description="Detected hardcoded credential value.",
                    code=code,
                    filepath=filepath,
                    line_number=idx,
                    confidence="0.95",
                ))
        return findings

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")

    def _register_advanced_hit(self, detector_name: str, line_number: int) -> None:
        self.advanced_hit_counter[detector_name] += 1
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "Advanced detector hit",
                extra={
                    "detector": detector_name,
                    "line": line_number,
                    "filepath": getattr(self, "file_path", "<unknown>")
                },
            )

    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        unique: Dict[tuple, Vulnerability] = {}
        for vuln in vulnerabilities:
            key = (vuln.cwe, vuln.line_number, vuln.code_snippet)
            if key not in unique:
                unique[key] = vuln
        return list(unique.values())

    def __getattr__(self, item: str):
        if item.startswith("detect_"):
            def _noop(*args, **kwargs) -> List[Vulnerability]:
                return []
            return _noop
        raise AttributeError(item)
