#!/usr/bin/env python3
from __future__ import annotations
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""YAML language security analyzer."""


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
    "detect_hardcoded_secrets": PatternRule(
        name="detect_hardcoded_secrets",
        cwe="CWE-798",
        severity="critical",
        title="Hardcoded Secret",
        description="Sensitive credentials embedded directly in YAML configuration.",
        patterns=[
            r"(?i)(password|secret|token|key|credential)[\w\-]*\s*:\s*[\"\']?[A-Za-z0-9/+=]{8,}[\"\']?",
            r"(?i)api[_-]?key\s*:\s*[\"\']?[A-Za-z0-9/+=]{8,}[\"\']?",
            r"(?i)access[_-]?token\s*:\s*[\"\']?[A-Za-z0-9/+=]{8,}[\"\']?",
        ],
        confidence=0.95,
    ),
    "detect_weak_crypto": PatternRule(
        name="detect_weak_crypto",
        cwe="CWE-327",
        severity="medium",
        title="Weak Cryptography Configuration",
        description="Configuration specifies weak cryptographic algorithms.",
        patterns=[
            r"(?i)cipher\s*:\s*[\"\']?(DES|MD5|RC4|SHA-1)[\"\']?",
            r"(?i)algorithm\s*:\s*[\"\']?(DES|MD5|RC4|SHA-1)[\"\']?",
            r"(?i)encryption\s*:\s*[\"\']?(DES|MD5|RC4|SHA-1)[\"\']?",
        ],
        confidence=0.8,
    ),
    "detect_insecure_ssl": PatternRule(
        name="detect_insecure_ssl",
        cwe="CWE-297",
        severity="high",
        title="Insecure SSL/TLS Configuration",
        description="SSL/TLS configuration allows insecure connections.",
        patterns=[
            r"(?i)verify_ssl\s*:\s*(false|no|0)",
            r"(?i)ssl_verify\s*:\s*(false|no|0)",
            r"(?i)insecure_skip_verify\s*:\s*(true|yes|1)",
            r"(?i)rejectUnauthorized\s*:\s*(false|no|0)",
        ],
        confidence=0.85,
    ),
    "detect_debug_enabled": PatternRule(
        name="detect_debug_enabled",
        cwe="CWE-489",
        severity="medium",
        title="Debug Mode Enabled",
        description="Debug mode is enabled in production configuration.",
        patterns=[
            r"(?i)debug\s*:\s*(true|yes|1)",
            r"(?i)debug_mode\s*:\s*(true|yes|1)",
            r"(?i)development\s*:\s*(true|yes|1)",
        ],
        confidence=0.7,
    ),
    "detect_open_permissions": PatternRule(
        name="detect_open_permissions",
        cwe="CWE-732",
        severity="medium",
        title="Overly Permissive Configuration",
        description="Configuration grants overly broad permissions.",
        patterns=[
            r"(?i)allow_all\s*:\s*(true|yes|1)",
            r"(?i)permit_all\s*:\s*(true|yes|1)",
            r"(?i)public_access\s*:\s*(true|yes|1)",
        ],
        confidence=0.75,
    ),
    "detect_sensitive_data_exposure": PatternRule(
        name="detect_sensitive_data_exposure",
        cwe="CWE-200",
        severity="high",
        title="Sensitive Data in Configuration",
        description="Sensitive data exposed in configuration files.",
        patterns=[
            r"(?i)(ssn|social_security|credit_card|bank_account)\s*:\s*[\"\']?[\d\-\s]{8,}[\"\']?",
            r"(?i)private_key\s*:\s*[\"\']?.{20,}[\"\']?",
            r"(?i)certificate\s*:\s*[\"\']?.{50,}[\"\']?",
        ],
        confidence=0.9,
        advanced=True,
    ),
    "detect_insecure_defaults": PatternRule(
        name="detect_insecure_defaults",
        cwe="CWE-1188",
        severity="low",
        title="Insecure Default Configuration",
        description="Configuration uses known insecure defaults.",
        patterns=[
            r"(?i)admin\s*:\s*[\"\']?(admin|root|user)[\"\']?",
            r"(?i)password\s*:\s*[\"\']?(password|123456|admin)[\"\']?",
        ],
        confidence=0.6,
    ),
}

ADVANCED_RULE_NAMES = {name for name, rule in PATTERN_RULES.items() if rule.advanced}


class YAMLAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for YAML configuration files."""

    ANALYZE_ORDER = [
        "detect_hardcoded_secrets",
        "detect_weak_crypto",
        "detect_insecure_ssl",
        "detect_debug_enabled",
        "detect_open_permissions",
        "detect_sensitive_data_exposure",
        "detect_insecure_defaults",
    ]

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.advanced_hit_counter: Counter[str] = Counter()

    def get_supported_cwes(self) -> List[str]:
        return [
            "CWE-200", "CWE-297", "CWE-327", "CWE-489", "CWE-732", "CWE-798", "CWE-1188",
        ]

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        self.logger.debug("Starting YAML analysis", extra={"filepath": filepath})
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
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_hardcoded_secrets", code, filepath)

    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_weak_crypto", code, filepath)

    def detect_insecure_ssl(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_ssl", code, filepath)

    def detect_debug_enabled(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_debug_enabled", code, filepath)

    def detect_open_permissions(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_open_permissions", code, filepath)

    def detect_sensitive_data_exposure(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_sensitive_data_exposure", code, filepath)

    def detect_insecure_defaults(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_defaults", code, filepath)

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
        return stripped.startswith("#")

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
