"""Python language security analyzer."""

from __future__ import annotations

import ast
import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

# Robust import
try:
    from .base import LanguageAnalyzer, Vulnerability
except ImportError:
    from valid8.base import LanguageAnalyzer, Vulnerability
# Robust import
try:
    from .universal_detectors import UniversalDetectors
except ImportError:
    from valid8.universal_detectors import UniversalDetectors
# Robust import
try:
    from ..codeql_analyzer import DataFlowAnalyzer
except ImportError:
    from valid8.codeql_analyzer import DataFlowAnalyzer
# Robust import
try:
    from ..framework_detectors import FrameworkDetectors
except ImportError:
    from valid8.framework_detectors import DjangoDetector, FlaskDetector


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
            r"os\.system\s*\(",
            r"subprocess\.(run|call|Popen)\s*\(",
            r"os\.popen\s*\(",
            r"commands\.getoutput\s*\(",
        ],
        evidence=None,  # Relaxed: any subprocess usage is suspicious
        confidence=0.6,  # Relaxed: lower confidence to catch more potential issues
    ),
    "detect_code_injection": PatternRule(
        name="detect_code_injection",
        cwe="CWE-94",
        severity="critical",
        title="Code Injection",
        description="Invocation of dynamic code execution primitives.",
        patterns=[
            r"eval\s*\(",
            r"exec\s*\(",
            r"compile\s*\(",
        ],
        evidence=None,  # Relaxed: any eval/exec usage is highly suspicious
        confidence=0.7,  # Relaxed: lower confidence but still critical
    ),
    "detect_sql_injection": PatternRule(
        name="detect_sql_injection",
        cwe="CWE-89",
        severity="critical",
        title="SQL Injection",
        description="Database query constructed with unsanitised user input.",
        patterns=[
            r"cursor\.(execute|executemany)\s*\(",
            r"session\.execute\s*\(",
            r"db\.query\s*\(",
        ],
        evidence=None,  # Relaxed: any execute() call with string formatting is suspicious
        confidence=0.5,  # Relaxed: very low confidence to catch all potential SQLi
    ),
    "detect_xss": PatternRule(
        name="detect_xss",
        cwe="CWE-79",
        severity="high",
        title="Cross-Site Scripting",
        description="HTML response built directly from user-controlled data.",
        patterns=[
            r"return\s+f?\".*<.*>.*",
            r"render_template_string\s*\(",
            r"response\.write\s*\(",
        ],
        evidence=None,  # Relaxed: any HTML output is potentially dangerous
        confidence=0.4,  # Relaxed: very low confidence to catch template injection
    ),
    "_detect_flask_xss": PatternRule(
        name="_detect_flask_xss",
        cwe="CWE-79",
        severity="high",
        title="Flask XSS",
        description="Flask template rendered with unsanitised user data.",
        patterns=[
            r"render_template\s*\(",
            r"make_response\s*\(",
        ],
        evidence=["request", "args", "form", "get_json"],
        confidence=0.75,
    ),
    "detect_path_traversal": PatternRule(
        name="detect_path_traversal",
        cwe="CWE-22",
        severity="high",
        title="Path Traversal",
        description="File system access constructed with user input.",
        patterns=[
            r"open\s*\(",
            r"os\.open\s*\(",
            r"pathlib\.Path\s*\(",
        ],
        evidence=None,  # Relaxed: any file operation is potentially dangerous
        confidence=0.3,  # Relaxed: very low confidence to catch all file operations
    ),
    "detect_weak_crypto": PatternRule(
        name="detect_weak_crypto",
        cwe="CWE-327",
        severity="medium",
        title="Weak Cryptography",
        description="Use of weak or insecure cryptographic primitives.",
        patterns=[
            r"hashlib\.md5",
            r"hashlib\.sha1",
            r"random\.random\s*\(",
            r"Crypto\.Cipher\.DES",
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
            r"(?i)(api|secret|token|key)[\w\-]*\s*=\s*[\"\'][A-Za-z0-9/+=]{8,}[\"']",
        ],
        confidence=0.9,
    ),
    "detect_hardcoded_password": PatternRule(
        name="detect_hardcoded_password",
        cwe="CWE-798",
        severity="critical",
        title="Hardcoded Password",
        description="Password value embedded directly in source code.",
        patterns=[
            r"(?i)password\s*=\s*[\"\'][A-Za-z0-9/+=]{4,}[\"']",
        ],
        confidence=0.95,
    ),
    "detect_open_redirect": PatternRule(
        name="detect_open_redirect",
        cwe="CWE-601",
        severity="medium",
        title="Open Redirect",
        description="Redirect destination derived from user input without validation.",
        patterns=[
            r"redirect\s*\(",
        ],
        evidence=["request", "args", "form", "next"],
        confidence=0.7,
    ),
    "detect_unsafe_deserialization": PatternRule(
        name="detect_unsafe_deserialization",
        cwe="CWE-502",
        severity="critical",
        title="Unsafe Deserialization",
        description="Use of unsafe deserialization routines with untrusted data.",
        patterns=[
            r"pickle\.loads",
            r"yaml\.load",
            r"marshal\.loads",
            r"jsonpickle\.decode",
        ],
        evidence=["request", "input", "data", "body"],
        confidence=0.85,
    ),
    "detect_xxe": PatternRule(
        name="detect_xxe",
        cwe="CWE-611",
        severity="critical",
        title="XML External Entity (XXE)",
        description="XML parser configured to process untrusted input.",
        patterns=[
            r"xml\.etree",
            r"lxml\.etree",
            r"ElementTree\.parse",
            r"defusedxml",
            r"ET\.(?:fromstring|XMLParser)",
        ],
        evidence=None,
        confidence=0.75,
        advanced=True,
    ),
    "detect_ssrf": PatternRule(
        name="detect_ssrf",
        cwe="CWE-918",
        severity="critical",
        title="Server-Side Request Forgery",
        description="HTTP client request built from user input.",
        patterns=[
            r"requests\.(get|post|put|delete)\s*\(",
            r"urllib\.request\.(urlopen|Request)\s*\(",
            r"httpx\.(get|post|AsyncClient)\s*\(",
        ],
        evidence=["request", "args", "form", "url", "input"],
        confidence=0.85,
        advanced=True,
    ),
    "detect_idor": PatternRule(
        name="detect_idor",
        cwe="CWE-639",
        severity="high",
        title="Insecure Direct Object Reference",
        description="Resource access determined solely by user-supplied identifiers.",
        patterns=[
            r"@app\.route.*<.*_id>",
            r"SELECT\s+.*\s+FROM.*WHERE.*id\s*=",
            r"cursor\.execute\s*\(f?\"SELECT.*WHERE.*id\s*=",
        ],
        evidence=None,
        confidence=0.8,
        advanced=True,
    ),
    "detect_information_disclosure": PatternRule(
        name="detect_information_disclosure",
        cwe="CWE-200",
        severity="medium",
        title="Information Disclosure",
        description="Sensitive information exposed through logging or responses.",
        patterns=[
            r"print\s*\(.*(password|secret|token)",
            r"log\.(debug|info|warning|error)\(.*(password|secret|token)",
            r"return\s+.*(password|secret|token)",
            r"app\.debug\s*=\s*True",
            r"['\"]password['\"]\s*:\s*['\"][^'\"]+",
            r"['\"]api_key['\"]\s*:\s*['\"][^'\"]+",
            r"traceback\.format_exc\s*\(",
            r"os\.uname\s*\(",
            r"os\.getcwd\s*\(",
        ],
        confidence=0.7,
        advanced=True,
    ),
    "detect_ssti": PatternRule(
        name="detect_ssti",
        cwe="CWE-94",
        severity="high",
        title="Server-Side Template Injection",
        description="Template rendering invoked with user-controlled expressions.",
        patterns=[
            r"render_template_string\s*\(",
            r"Template\(.*\{\{",
        ],
        evidence=["request", "args", "form", "format"],
        confidence=0.8,
    ),
    "detect_nosql_injection": PatternRule(
        name="detect_nosql_injection",
        cwe="CWE-943",
        severity="high",
        title="NoSQL Injection",
        description="NoSQL query built directly from user input.",
        patterns=[
            r"find\s*\(.*request",
            r"aggregate\s*\(.*\$where",
            r"db\.[a-zA-Z0-9_]+\.find\s*\(",
        ],
        evidence=None,  # Relaxed: any NoSQL operation is potentially dangerous
        confidence=0.6,  # Relaxed: lower confidence
    ),
    "detect_ldap_injection": PatternRule(
        name="detect_ldap_injection",
        cwe="CWE-90",
        severity="critical",
        title="LDAP Injection",
        description="LDAP query constructed with unsanitised user input.",
        patterns=[
            r"ldap\.search",
            r"ldap\.bind",
            r"django_auth_ldap",
        ],
        evidence=None,  # Relaxed: any LDAP operation with input
        confidence=0.7,
        advanced=True,
    ),
    "detect_xpath_injection": PatternRule(
        name="detect_xpath_injection",
        cwe="CWE-643",
        severity="high",
        title="XPath Injection",
        description="XPath query built directly from user input.",
        patterns=[
            r"etree\.xpath",
            r"xml\.xpath",
            r"XPathEvaluate",
        ],
        evidence=None,  # Relaxed: any XPath operation
        confidence=0.6,
        advanced=True,
    ),
    "detect_log_injection": PatternRule(
        name="detect_log_injection",
        cwe="CWE-117",
        severity="medium",
        title="Log Injection",
        description="User input written directly to logs.",
        patterns=[
            r"log\.(info|debug|warning|error)\s*\(.*\+",
            r"logging\.(info|debug|warning|error)\s*\(.*%",
            r"print\s*\(.*\+.*request",
        ],
        evidence=None,  # Relaxed: any logging with string concatenation
        confidence=0.4,  # Relaxed: very low confidence
    ),
    "detect_insecure_random": PatternRule(
        name="detect_insecure_random",
        cwe="CWE-338",
        severity="medium",
        title="Insecure Random",
        description="Use of predictable random number generators.",
        patterns=[
            r"random\.(randint|choice|random)",
            r"SystemRandom",  # This is actually secure, but context matters
        ],
        evidence=None,  # Relaxed: flag all random usage for review
        confidence=0.3,  # Relaxed: very low confidence
    ),
    "detect_buffer_overflow": PatternRule(
        name="detect_buffer_overflow",
        cwe="CWE-119",
        severity="critical",
        title="Buffer Overflow",
        description="Potential buffer overflow vulnerabilities.",
        patterns=[
            r"bytearray\s*\(\s*\d+\s*\)",
            r"array\.array\s*\(",
            r"ctypes\.",
        ],
        evidence=None,  # Relaxed: any low-level memory operation
        confidence=0.5,
        advanced=True,
    ),
    "detect_race_condition": PatternRule(
        name="detect_race_condition",
        cwe="CWE-362",
        severity="high",
        title="Race Condition",
        description="Potential race condition in file operations.",
        patterns=[
            r"if\s+os\.path\.exists\s*\(",
            r"with\s+open\s*\(.*\+",
            r"os\.rename\s*\(",
        ],
        evidence=None,  # Relaxed: any conditional file operation
        confidence=0.4,
        advanced=True,
    ),
    "detect_insecure_pickle": PatternRule(
        name="detect_insecure_pickle",
        cwe="CWE-502",
        severity="critical",
        title="Insecure Deserialization (Pickle)",
        description="Use of pickle for deserialization.",
        patterns=[
            r"pickle\.loads\s*\(",
            r"pickle\.load\s*\(",
            r"cPickle\.",
        ],
        evidence=None,  # Relaxed: any pickle usage is dangerous
        confidence=0.8,
    ),
}

ADVANCED_RULE_NAMES = {name for name, rule in PATTERN_RULES.items() if rule.advanced}


class PythonAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Python source files."""

    ANALYZE_ORDER = [
        "detect_command_injection",
        "detect_code_injection",
        "detect_sql_injection",
        "detect_xss",
        "_detect_flask_xss",
        "detect_path_traversal",
        "detect_weak_crypto",
        "detect_hardcoded_secrets",
        "detect_hardcoded_password",
        "detect_open_redirect",
        "detect_unsafe_deserialization",
        "detect_insecure_pickle",
        "detect_xxe",
        "detect_ssrf",
        "detect_ldap_injection",
        "detect_xpath_injection",
        "detect_idor",
        "detect_log_injection",
        "detect_insecure_random",
        "detect_buffer_overflow",
        "detect_race_condition",
        "detect_information_disclosure",
        "detect_ssti",
        "detect_nosql_injection",
    ]

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.django_detector = DjangoDetector()
        self.flask_detector = FlaskDetector()
        self.advanced_hit_counter: Counter[str] = Counter()

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def get_supported_cwes(self) -> List[str]:
        return [
            "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
            "CWE-94", "CWE-95", "CWE-117", "CWE-119", "CWE-200", "CWE-287",
            "CWE-327", "CWE-338", "CWE-352", "CWE-362", "CWE-502", "CWE-611",
            "CWE-639", "CWE-643", "CWE-918", "CWE-943", "CWE-798",
        ]

    def parse_ast(self, code: str) -> Optional[ast.AST]:
        try:
            return ast.parse(code)
        except SyntaxError:
            return None

    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        self.logger.debug("Starting Python analysis", extra={"filepath": filepath})
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
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.debug("Detector %s failed: %s", detector_name, exc)

        vulnerabilities.extend(self._detect_critical_credentials(code, filepath))

        # Universal, language-agnostic detectors from the mixin
        universal_detectors = [
            self.detect_improper_input_validation,
            self.detect_information_exposure,
            self.detect_improper_authentication,
            self.detect_csrf,
            self.detect_graphql_security,
            self.detect_jwt_security,
            self.detect_nosql_injection,  # already executed above but harmless duplicates filtered later
            self.detect_ssti,             # likewise
            self.detect_redos,
            self.detect_incorrect_permissions,
        ]

        for detector in universal_detectors:
            try:
                vulnerabilities.extend(detector(code, filepath))
            except Exception as exc:  # pragma: no cover
                self.logger.debug("Universal detector %s failed: %s", detector.__name__, exc)

        # Data flow analysis (best-effort)
        try:
            data_flow_vulns = self.data_flow_analyzer.analyze(code, filepath)
            vulnerabilities.extend(data_flow_vulns)
        except Exception as exc:  # pragma: no cover
            self.logger.debug("Data flow analysis failed: %s", exc)

        # Framework-specific heuristics
        lowered = code.lower()
        try:
            if "django" in lowered:
                vulnerabilities.extend(self.django_detector.detect(code, filepath))
            if "flask" in lowered:
                vulnerabilities.extend(self.flask_detector.detect(code, filepath))
        except Exception as exc:  # pragma: no cover
            self.logger.debug("Framework detector failure: %s", exc)

        return self._deduplicate(vulnerabilities)

    def get_advanced_detector_stats(self) -> Dict[str, int]:
        return dict(self.advanced_hit_counter)

    # ------------------------------------------------------------------
    # Individual detector implementations
    # ------------------------------------------------------------------
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_command_injection", code, filepath)

    def detect_code_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_code_injection", code, filepath)

    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_sql_injection", code, filepath)

    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_xss", code, filepath)

    def _detect_flask_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("_detect_flask_xss", code, filepath)

    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_path_traversal", code, filepath)

    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_weak_crypto", code, filepath)

    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_hardcoded_secrets", code, filepath)

    def detect_hardcoded_password(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_hardcoded_password", code, filepath)

    def detect_open_redirect(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_open_redirect", code, filepath)

    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_unsafe_deserialization", code, filepath)

    def detect_xxe(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_xxe", code, filepath)

    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_ssrf", code, filepath)

    def detect_idor(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_idor", code, filepath)

    def detect_information_disclosure(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_information_disclosure", code, filepath)

    def detect_ssti(self, code: str, filepath: str) -> List[Vulnerability]:  # type: ignore[override]
        return self._run_rule("detect_ssti", code, filepath)

    def detect_nosql_injection(self, code: str, filepath: str) -> List[Vulnerability]:  # type: ignore[override]
        return self._run_rule("detect_nosql_injection", code, filepath)

    def detect_ldap_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_ldap_injection", code, filepath)

    def detect_xpath_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_xpath_injection", code, filepath)

    def detect_log_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_log_injection", code, filepath)

    def detect_insecure_random(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_random", code, filepath)

    def detect_buffer_overflow(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_buffer_overflow", code, filepath)

    def detect_race_condition(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_race_condition", code, filepath)

    def detect_insecure_pickle(self, code: str, filepath: str) -> List[Vulnerability]:
        return self._run_rule("detect_insecure_pickle", code, filepath)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
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

            # Relaxed detection: only skip if we have strict evidence requirements
            # If evidence is None, we flag all pattern matches as potential issues
            if rule.evidence is not None and not any(token in line for token in rule.evidence):
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
            re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*[\"\'][A-Za-z0-9/+=]{20,}[\"']"),
            re.compile(r"(?i)AWS_ACCESS_KEY_ID\s*=\s*[\"\'][A-Z0-9]{16,}[\"']"),
            re.compile(r"(?i)(PRIVATE|PUBLIC)_KEY\s*=\s*[\"\'][^-\n]{24,}[\"']"),
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
        return stripped.startswith("#") or stripped.startswith("'''") or stripped.startswith('"""')

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

    def __getattr__(self, item: str):  # pragma: no cover - defensive
        if item.startswith("detect_"):
            def _noop(*args, **kwargs) -> List[Vulnerability]:
                return []
            return _noop
        raise AttributeError(item)


