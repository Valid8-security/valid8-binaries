"""SQL language security analyzer."""

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
    "detect_sql_injection": PatternRule(
        name="detect_sql_injection",
        cwe="CWE-89",
        severity="critical",
        title="SQL Injection",
        description="SQL query constructed with unsanitised user input.",
        patterns=[
            r"SELECT\s+.*WHERE.*=.*\+",
            r"INSERT\s+.*VALUES.*\+",
            r"UPDATE\s+.*SET.*\+",
            r"DELETE\s+.*WHERE.*\+",
            r"EXEC\s+.*\+",
            r"EXECUTE\s+.*\+",
        ],
        evidence=["$user_input", "@param", "request"],
        confidence=0.9,
    ),
    "detect_weak_auth": PatternRule(
        name="detect_weak_auth",
        cwe="CWE-287",
        severity="high",
        title="Weak Authentication",
        description="Weak or missing authentication mechanisms.",
        patterns=[
            r"PASSWORD\s*=\s*['\"][^'\"]{0,3}['\"]",  # Very short passwords
            r"admin.*123",  # Weak default passwords
            r"password.*password",
        ],
        confidence=0.8,
    ),
    "detect_information_disclosure": PatternRule(
        name="detect_information_disclosure",
        cwe="CWE-200",
        severity="medium",
        title="Information Disclosure",
        description="Sensitive information exposed in database.",
        patterns=[
            r"SELECT\s+.*password",
            r"SELECT\s+.*ssn",
            r"SELECT\s+.*credit_card",
            r"SELECT\s+.*social_security",
        ],
        confidence=0.7,
    ),
    "detect_insecure_permissions": PatternRule(
        name="detect_insecure_permissions",
        cwe="CWE-732",
        severity="medium",
        title="Insecure Permissions",
        description="Overly permissive database permissions.",
        patterns=[
            r"GRANT\s+ALL\s+PRIVILEGES",
            r"GRANT\s+.*TO\s+.*%",
            r"PUBLIC\s+.*GRANT",
        ],
        confidence=0.75,
    ),
    "detect_hardcoded_credentials": PatternRule(
        name="detect_hardcoded_credentials",
        cwe="CWE-798",
        severity="critical",
        title="Hardcoded Credentials",
        description="Database credentials hardcoded in SQL.",
        patterns=[
            r"(?i)USER\s*=\s*['\"][^'\"]{3,}['\"]",
            r"(?i)PASSWORD\s*=\s*['\"][^'\"]{3,}['\"]",
            r"(?i)CONNECT\s+.*USER.*PASSWORD",
        ],
        confidence=0.9,
    ),
    "detect_unencrypted_connection": PatternRule(
        name="detect_unencrypted_connection",
        cwe="CWE-319",
        severity="medium",
        title="Unencrypted Connection",
        description="Database connection not using encryption.",
        patterns=[
            r"CONNECT\s+.*ENCRYPT.*FALSE",
            r"SSL.*DISABLE",
            r"ENCRYPTION.*OFF",
        ],
        confidence=0.8,
        advanced=True,
    ),
    "detect_insecure_functions": PatternRule(
        name="detect_insecure_functions",
        cwe="CWE-94",
        severity="high",
        title="Insecure SQL Functions",
        description="Use of potentially dangerous SQL functions.",
        patterns=[
            r"EXEC\s*\(",
            r"EXECUTE\s*\(",
            r"xp_cmdshell",
            r"sp_execute",
        ],
        confidence=0.85,
    ),
}

ADVANCED_RULE_NAMES = {name for name, rule in PATTERN_RULES.items() if rule.advanced}


class SQLAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for SQL source files."""

    ANALYZE_ORDER = [
        "detect_sql_injection",
        "detect_weak_auth",
        "detect_information_disclosure",
        "detect_insecure_permissions",
        "detect_hardcoded_credentials",
        "detect_unencrypted_connection",
        "detect_insecure_functions",
    ]

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.advanced_hit_counter: Counter[str] = Counter()

    def get_supported_cwes(self) -> List[str]:
        return [
            "CWE-89", "CWE-200", "CWE-287", "CWE-319", "CWE-732", "CWE-798", "CWE-94",
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        self.logger.debug("Starting SQL analysis", extra={"filepath": filepath})
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
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_sql_injection", code, filepath)

    def detect_weak_auth(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_weak_auth", code, filepath)

    def detect_information_disclosure(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_information_disclosure", code, filepath)

    def detect_insecure_permissions(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_permissions", code, filepath)

    def detect_hardcoded_credentials(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_hardcoded_credentials", code, filepath)

    def detect_unencrypted_connection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_unencrypted_connection", code, filepath)

    def detect_insecure_functions(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_functions", code, filepath)

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

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("--") or stripped.startswith("/*")

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
