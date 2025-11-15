#!/usr/bin/env python3
"""
Script to generate comprehensive language analyzers for Valid8.
Creates analyzers for all supported languages with extensive CWE coverage.
"""

import os
from typing import Dict, List

# Template for language analyzers
TEMPLATE = '''"""{{LANGUAGE}} language security analyzer."""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors
from ..data_flow_analyzer import DataFlowAnalyzer


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
        patterns={{COMMAND_PATTERNS}},
        evidence={{COMMAND_EVIDENCE}},
        confidence=0.9,
    ),
    "detect_code_injection": PatternRule(
        name="detect_code_injection",
        cwe="CWE-94",
        severity="critical",
        title="Code Injection",
        description="Invocation of dynamic code execution primitives.",
        patterns={{CODE_PATTERNS}},
        evidence={{CODE_EVIDENCE}},
        confidence=0.9,
    ),
    "detect_sql_injection": PatternRule(
        name="detect_sql_injection",
        cwe="CWE-89",
        severity="critical",
        title="SQL Injection",
        description="Database query constructed with unsanitised user input.",
        patterns={{SQL_PATTERNS}},
        evidence={{SQL_EVIDENCE}},
        confidence=0.85,
    ),
    "detect_xss": PatternRule(
        name="detect_xss",
        cwe="CWE-79",
        severity="high",
        title="Cross-Site Scripting",
        description="HTML response built directly from user-controlled data.",
        patterns={{XSS_PATTERNS}},
        evidence={{XSS_EVIDENCE}},
        confidence=0.8,
    ),
    "detect_path_traversal": PatternRule(
        name="detect_path_traversal",
        cwe="CWE-22",
        severity="high",
        title="Path Traversal",
        description="File system access constructed with user input.",
        patterns={{PATH_PATTERNS}},
        evidence={{PATH_EVIDENCE}},
        confidence=0.8,
    ),
    "detect_weak_crypto": PatternRule(
        name="detect_weak_crypto",
        cwe="CWE-327",
        severity="medium",
        title="Weak Cryptography",
        description="Use of weak or insecure cryptographic primitives.",
        patterns={{CRYPTO_PATTERNS}},
        confidence=0.75,
    ),
    "detect_hardcoded_secrets": PatternRule(
        name="detect_hardcoded_secrets",
        cwe="CWE-798",
        severity="critical",
        title="Hardcoded Secret",
        description="Sensitive token or credential embedded directly in source code.",
        patterns=[
            r"(?i)(api|secret|token|key)[\\w\\-]*\\s*[:=]\\s*[\\"'][A-Za-z0-9/+=]{8,}[\\"']",
        ],
        confidence=0.9,
    ),
    "detect_insecure_deserialization": PatternRule(
        name="detect_insecure_deserialization",
        cwe="CWE-502",
        severity="critical",
        title="Unsafe Deserialization",
        description="Use of unsafe deserialization routines with untrusted data.",
        patterns={{DESERIALIZE_PATTERNS}},
        evidence={{DESERIALIZE_EVIDENCE}},
        confidence=0.85,
    ),
    "detect_ssrf": PatternRule(
        name="detect_ssrf",
        cwe="CWE-918",
        severity="critical",
        title="Server-Side Request Forgery",
        description="HTTP client request built from user input.",
        patterns={{SSRF_PATTERNS}},
        evidence={{SSRF_EVIDENCE}},
        confidence=0.85,
        advanced=True,
    ),
    "detect_open_redirect": PatternRule(
        name="detect_open_redirect",
        cwe="CWE-601",
        severity="medium",
        title="Open Redirect",
        description="Redirect destination derived from user input without validation.",
        patterns={{REDIRECT_PATTERNS}},
        evidence={{REDIRECT_EVIDENCE}},
        confidence=0.7,
    ),
    "detect_information_disclosure": PatternRule(
        name="detect_information_disclosure",
        cwe="CWE-200",
        severity="medium",
        title="Information Disclosure",
        description="Sensitive information exposed through logging or responses.",
        patterns={{INFO_PATTERNS}},
        confidence=0.7,
        advanced=True,
    ),
}

ADVANCED_RULE_NAMES = {name for name, rule in PATTERN_RULES.items() if rule.advanced}


class {{CLASS_NAME}}Analyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for {{LANGUAGE}} source files."""

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
        self.logger.debug("Starting {{LANGUAGE}} analysis", extra={"filepath": filepath})
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
            re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\\s*[:=]\\s*[\\"'][A-Za-z0-9/+=]{20,}[\\"']"),
            re.compile(r"(?i)AWS_ACCESS_KEY_ID\\s*[:=]\\s*[\\"'][A-Z0-9]{16,}[\\"']"),
            re.compile(r"(?i)(PRIVATE|PUBLIC)_KEY\\s*[:=]\\s*[\\"'][^-\n]{24,}[\\"']"),
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
        {{COMMENT_CHECK}}
        return False

    def _register_advanced_hit(self, detector_name: str, line_number: int) -> None:
        self.advanced_hit_counter[detector_name] += 1
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "Advanced detector hit",
                extra={{
                    "detector": detector_name,
                    "line": line_number,
                    "filepath": getattr(self, "file_path", "<unknown>")
                }},
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
'''

# Language configurations
LANGUAGES = {
    "kotlin": {
        "language": "Kotlin",
        "class_name": "Kotlin",
        "command_patterns": [r"ProcessBuilder", r"Runtime\.getRuntime", r"exec\s*\("],
        "command_evidence": '["request", "params", "input"]',
        "code_patterns": ['r"eval\\s*\\("'],
        "code_evidence": '["request", "params", "input"]',
        "sql_patterns": ['r"\\.execute", r"rawQuery", r"compileStatement"'],
        "sql_evidence": '["request", "params", "+", "format"]',
        "xss_patterns": ['r"\\.text\\s*=", r"Html\\.fromHtml"'],
        "xss_evidence": '["request", "params", "input"]',
        "path_patterns": ['r"File\\(", r"FileInputStream", r"Paths\\.get"'],
        "path_evidence": '["../", "..\\\\", "request", "params"]',
        "crypto_patterns": ['r"MD5", r"SHA-1", r"DES"'],
        "deserialize_patterns": ['r"ObjectInputStream", r"Gson\\.fromJson"'],
        "deserialize_evidence": '["request", "params"]',
        "ssrf_patterns": ['r"HttpURLConnection", r"OkHttpClient", r"URL\\.openConnection"'],
        "ssrf_evidence": '["request", "params"]',
        "redirect_patterns": ['r"startActivity", r"Intent"'],
        "redirect_evidence": '["request", "params"]',
        "info_patterns": ['r"Log\\.d.*(password|secret)", r"println.*(password|secret)"]',
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
    "scala": {
        "language": "Scala",
        "class_name": "Scala",
        "command_patterns": ['r"Process\\(", r"sys\\.process", r"!\\s"'],
        "command_evidence": '["request", "params", "input"]',
        "code_patterns": ['r"eval\\s*\\("'],
        "code_evidence": '["request", "params", "input"]',
        "sql_patterns": ['r"\\.execute", r"sql\\"'],
        "sql_evidence": '["request", "params", "+", "format"]',
        "xss_patterns": ['r"\\.innerHTML\\s*=", r"Html"'],
        "xss_evidence": '["request", "params", "input"]',
        "path_patterns": ['r"new File\\(", r"Paths\\.get", r"Source\\.fromFile"'],
        "path_evidence": '["../", "..\\\\", "request", "params"]',
        "crypto_patterns": ['r"MD5", r"SHA-1", r"DES"'],
        "deserialize_patterns": ['r"ObjectInputStream", r"Json\\.parse"'],
        "deserialize_evidence": '["request", "params"]',
        "ssrf_patterns": ['r"Http\\(", r"WSClient", r"URL"'],
        "ssrf_evidence": '["request", "params"]',
        "redirect_patterns": ['r"Redirect"'],
        "redirect_evidence": '["request", "params"]',
        "info_patterns": ['r"println.*(password|secret)", r"log.*(password|secret)"]',
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
    "swift": {
        "language": "Swift",
        "class_name": "Swift",
        "command_patterns": ['r"Process\\(", r"shell\\(", r"system\\("'],
        "command_evidence": '["request", "params", "input"]',
        "code_patterns": ['r"NSExpression", r"evaluate"'],
        "code_evidence": '["request", "params", "input"]',
        "sql_patterns": ['r"\\.execute", r"sqlite3"'],
        "sql_evidence": '["request", "params", "+", "stringFormat"]',
        "xss_patterns": ['r"\\.innerHTML\\s*=", r"javascript:"'],
        "xss_evidence": '["request", "params", "input"]',
        "path_patterns": ['r"FileManager", r"URL\\(fileURLWithPath", r"NSString"'],
        "path_evidence": '["../", "..\\\\", "request", "params"]',
        "crypto_patterns": ['r"MD5", r"SHA1", r"DES"'],
        "deserialize_patterns": ['r"NSKeyedUnarchiver", r"JSONDecoder"'],
        "deserialize_evidence": '["request", "params"]',
        "ssrf_patterns": ['r"URLSession", r"HttpRequest", r"URL"'],
        "ssrf_evidence": '["request", "params"]',
        "redirect_patterns": ['r"openURL", r"UIApplication"'],
        "redirect_evidence": '["request", "params"]',
        "info_patterns": ['r"print.*(password|secret)", r"debugPrint.*(password|secret)"]',
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
    "php": {
        "language": "PHP",
        "class_name": "PHP",
        "command_patterns": ['r"exec\\s*\\(", r"system\\s*\\(", r"shell_exec\\s*\\(", r"passthru\\s*\\("'],
        "command_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "code_patterns": ['r"eval\\s*\\(", r"assert\\s*\\(", r"create_function\\s*\\("'],
        "code_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "sql_patterns": ['r"mysql_query\\s*\\(", r"mysqli_query\\s*\\(", r"pg_query\\s*\\("'],
        "sql_evidence": ['"$_GET", "$_POST", "$_REQUEST", "$sql"'],
        "xss_patterns": ['r"echo\\s+", r"print\\s+", r"printf\\s*\\("'],
        "xss_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "path_patterns": ['r"fopen\\s*\\(", r"file_get_contents\\s*\\(", r"include\\s+", r"require\\s+"'],
        "path_evidence": ['"../", "..\\\\", "$_GET", "$_POST"'],
        "crypto_patterns": ['r"md5\\s*\\(", r"sha1\\s*\\(", r"crc32\\s*\\("'],
        "deserialize_patterns": ['r"unserialize\\s*\\(", r"json_decode\\s*\\("'],
        "deserialize_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "ssrf_patterns": ['r"curl_exec\\s*\\(", r"file_get_contents\\s*\\(", r"fopen\\s*\\("],
        "ssrf_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "redirect_patterns": ['r"header\\s*\\(.*Location"'],
        "redirect_evidence": ['"$_GET", "$_POST", "$_REQUEST"'],
        "info_patterns": ['r"echo.*(password|secret)", r"print.*(password|secret)"]',
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*")',
    },
    "ruby": {
        "language": "Ruby",
        "class_name": "Ruby",
        "command_patterns": ['r"`", r"system\\s*\\(", r"exec\\s*\\(", r"\\%x\\{"'],
        "command_evidence": ['"params", "request"'],
        "code_patterns": ['r"eval\\s*\\(", r"instance_eval"'],
        "code_evidence": ['"params", "request"'],
        "sql_patterns": ['r"\\.execute", r"ActiveRecord"'],
        "sql_evidence": ['"params", "request", "+"'],
        "xss_patterns": ['r"html_safe", r"raw\\s+"'],
        "xss_evidence": ['"params", "request"'],
        "path_patterns": ['r"File\\.open", r"File\\.read", r"IO\\.read"'],
        "path_evidence": ['"../", "..\\\\", "params", "request"'],
        "crypto_patterns": ['r"Digest::MD5", r"Digest::SHA1", r"DES"'],
        "deserialize_patterns": ['r"Marshal\\.load", r"JSON\\.parse"'],
        "deserialize_evidence": ['"params", "request"'],
        "ssrf_patterns": ['r"Net::HTTP", r"open-uri", r"URI"'],
        "ssrf_evidence": ['"params", "request"'],
        "redirect_patterns": ['r"redirect_to"'],
        "redirect_evidence": ['"params", "request"'],
        "info_patterns": ['r"puts.*(password|secret)", r"p.*(password|secret)"]',
        "comment_check": 'return stripped.startswith("#")',
    },
    "perl": {
        "language": "Perl",
        "class_name": "Perl",
        "command_patterns": ['r"`", r"system\\s+", r"exec\\s+"'],
        "command_evidence": ['"$cgi", "$param"'],
        "code_patterns": ['r"eval\\s+"'],
        "code_evidence": ['"$cgi", "$param"'],
        "sql_patterns": ['r"->execute", r"DBI->"'],
        "sql_evidence": ['"$cgi", "$param", "."'],
        "xss_patterns": ['r"print\\s+", r"printf\\s+"'],
        "xss_evidence": ['"$cgi", "$param"'],
        "path_patterns": ['r"open\\s*\\(", r"File::open"'],
        "path_evidence": ['"../", "..\\\\", "$cgi", "$param"'],
        "crypto_patterns": ['r"Digest::MD5", r"Digest::SHA1"'],
        "deserialize_patterns": ['r"Storable::thaw", r"JSON::decode_json"'],
        "deserialize_evidence": ['"$cgi", "$param"'],
        "ssrf_patterns": ['r"LWP::UserAgent", r"HTTP::Request"'],
        "ssrf_evidence": ['"$cgi", "$param"'],
        "redirect_patterns": ['r"Location:"'],
        "redirect_evidence": ['"$cgi", "$param"'],
        "info_patterns": ['r"print.*(password|secret)"'],
        "comment_check": 'return stripped.startswith("#")',
    },
    "lua": {
        "language": "Lua",
        "class_name": "Lua",
        "command_patterns": ['r"os\\.execute", r"io\\.popen"'],
        "command_evidence": ['"request", "params"'],
        "code_patterns": ['r"load\\s*\\(", r"loadstring\\s*\\("'],
        "code_evidence": ['"request", "params"'],
        "sql_patterns": ['r":execute", r"sqlite3"'],
        "sql_evidence": ['"request", "params", ".."'],
        "xss_patterns": ['r"print\\s+", r"ngx\\.say"'],
        "xss_evidence": ['"request", "params"'],
        "path_patterns": ['r"io\\.open", r"lfs\\.attributes"'],
        "path_evidence": ['"../", "..\\\\", "request", "params"'],
        "crypto_patterns": ['r"md5", r"sha1"'],
        "deserialize_patterns": ['r"load", r"JSON:decode"'],
        "deserialize_evidence": ['"request", "params"'],
        "ssrf_patterns": ['r"http\\.request", r"curl"'],
        "ssrf_evidence": ['"request", "params"'],
        "redirect_patterns": ['r"ngx\\.redirect"'],
        "redirect_evidence": ['"request", "params"'],
        "info_patterns": ['r"print.*(password|secret)"'],
        "comment_check": 'return stripped.startswith("--")',
    },
    "haskell": {
        "language": "Haskell",
        "class_name": "Haskell",
        "command_patterns": ['r"system", r"rawSystem", r"callProcess"'],
        "command_evidence": ['"request", "params"'],
        "code_patterns": ['r"unsafePerformIO", r"read"'],
        "code_evidence": ['"request", "params"'],
        "sql_patterns": ['r"query", r"execute"'],
        "sql_evidence": ['"request", "params", "++"'],
        "xss_patterns": ['r"putStr", r"hPutStr"'],
        "xss_evidence": ['"request", "params"'],
        "path_patterns": ['r"readFile", r"writeFile", r"openFile"'],
        "path_evidence": ['"../", "..\\\\", "request", "params"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"read", r"decode"'],
        "deserialize_evidence": ['"request", "params"'],
        "ssrf_patterns": ['r"httpLbs", r"simpleHttp"'],
        "ssrf_evidence": ['"request", "params"'],
        "redirect_patterns": ['r"redirect"'],
        "redirect_evidence": ['"request", "params"'],
        "info_patterns": ['r"putStr.*password", r"putStr.*secret"'],
        "comment_check": 'return stripped.startswith("--")',
    },
    "clojure": {
        "language": "Clojure",
        "class_name": "Clojure",
        "command_patterns": ['r"sh", r"clojure.java.shell/sh"'],
        "command_evidence": ['"params", "request"'],
        "code_patterns": ['r"eval", r"read-string"'],
        "code_evidence": ['"params", "request"'],
        "sql_patterns": ['r"execute!", r"query"'],
        "sql_evidence": ['"params", "request", "str"'],
        "xss_patterns": ['r"hiccup", r"html"'],
        "xss_evidence": ['"params", "request"'],
        "path_patterns": ['r"slurp", r"spit", r"io/file"'],
        "path_evidence": ['"../", "..\\\\", "params", "request"'],
        "crypto_patterns": ['r"md5", r"sha1"'],
        "deserialize_patterns": ['r"read-string", r"json/parse-string"'],
        "deserialize_evidence": ['"params", "request"'],
        "ssrf_patterns": ['r"http/get", r"client/get"'],
        "ssrf_evidence": ['"params", "request"'],
        "redirect_patterns": ['r"redirect"'],
        "redirect_evidence": ['"params", "request"'],
        "info_patterns": ['r"println.*password", r"println.*secret"'],
        "comment_check": 'return stripped.startswith(";")',
    },
    "erlang": {
        "language": "Erlang",
        "class_name": "Erlang",
        "command_patterns": ['r"os:cmd", r"open_port"'],
        "command_evidence": ['"Req", "Params"'],
        "code_patterns": ['r"eval", r"apply"'],
        "code_evidence": ['"Req", "Params"'],
        "sql_patterns": ['r"execute", r"query"'],
        "sql_evidence": ['"Req", "Params", "++"'],
        "xss_patterns": ['r"wf:f"'],
        "xss_evidence": ['"Req", "Params"'],
        "path_patterns": ['r"file:read_file", r"file:open"'],
        "path_evidence": ['"../", "..\\\\", "Req", "Params"'],
        "crypto_patterns": ['r"md5", r"sha"'],
        "deserialize_patterns": ['r"binary_to_term", r"decode"'],
        "deserialize_evidence": ['"Req", "Params"'],
        "ssrf_patterns": ['r"httpc:request", r"http:request"'],
        "ssrf_evidence": ['"Req", "Params"'],
        "redirect_patterns": ['r"redirect"'],
        "redirect_evidence": ['"Req", "Params"'],
        "info_patterns": ['r"io:format.*password", r"io:format.*secret"'],
        "comment_check": 'return stripped.startswith("%")',
    },
    "bash": {
        "language": "Bash",
        "class_name": "Bash",
        "command_patterns": ['r"\\$\\(", r"`", r"eval\\s+"'],
        "command_evidence": ['"$1", "$@", "$*"'],
        "code_patterns": ['r"eval\\s+", r"source\\s+"'],
        "code_evidence": ['"$1", "$@", "$*"'],
        "sql_patterns": ['r"mysql", r"psql"'],
        "sql_evidence": ['"$1", "$@", "$*"'],
        "xss_patterns": ['r"echo\\s+", r"printf\\s+"'],
        "xss_evidence": ['"$1", "$@", "$*"'],
        "path_patterns": ['r"cat\\s+", r"<", r">"'],
        "path_evidence": ['"../", "..\\\\", "$1", "$@", "$*"'],
        "crypto_patterns": ['r"md5sum", r"sha1sum"'],
        "deserialize_patterns": ['r"source", r"."'],
        "deserialize_evidence": ['"$1", "$@", "$*"'],
        "ssrf_patterns": ['r"curl", r"wget"'],
        "ssrf_evidence": ['"$1", "$@", "$*"'],
        "redirect_patterns": ['r"exit", r"return"'],
        "redirect_evidence": ['"$1", "$@", "$*"'],
        "info_patterns": ['r"echo.*password", r"echo.*secret"'],
        "comment_check": 'return stripped.startswith("#")',
    },
    "powershell": {
        "language": "PowerShell",
        "class_name": "PowerShell",
        "command_patterns": ['r"Start-Process", r"&", r"Invoke-Expression"'],
        "command_evidence": ['"$args", "$input"'],
        "code_patterns": ['r"Invoke-Expression", r"&"'],
        "code_evidence": ['"$args", "$input"'],
        "sql_patterns": ['r"Invoke-Sqlcmd"'],
        "sql_evidence": ['"$args", "$input"'],
        "xss_patterns": ['r"Write-Host", r"Write-Output"'],
        "xss_evidence": ['"$args", "$input"'],
        "path_patterns": ['r"Get-Content", r"Set-Content", r"Test-Path"'],
        "path_evidence": ['"..\\\\", "$args", "$input"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"ConvertFrom-Json", r"Import-Clixml"'],
        "deserialize_evidence": ['"$args", "$input"'],
        "ssrf_patterns": ['r"Invoke-WebRequest", r"Invoke-RestMethod"'],
        "ssrf_evidence": ['"$args", "$input"'],
        "redirect_patterns": ['r"Start-Process"'],
        "redirect_evidence": ['"$args", "$input"'],
        "info_patterns": ['r"Write-Host.*password", r"Write-Host.*secret"'],
        "comment_check": 'return stripped.startswith("#")',
    },
    "c": {
        "language": "C",
        "class_name": "C",
        "command_patterns": ['r"system\\s*\\(", r"popen\\s*\\(", r"exec"'],
        "command_evidence": ['"argv", "input"'],
        "code_patterns": ['r"system\\s*\\("],
        "code_evidence": ['"argv", "input"'],
        "sql_patterns": ['r"mysql_query", r"sqlite3_exec"'],
        "sql_evidence": ['"argv", "input", "strcat", "sprintf"'],
        "xss_patterns": ['r"printf\\s*\\(", r"puts\\s*\\("],
        "xss_evidence": ['"argv", "input"'],
        "path_patterns": ['r"fopen\\s*\\(", r"open\\s*\\("],
        "path_evidence": ['"../", "..\\\\", "argv", "input"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"unserialize"'],
        "deserialize_evidence": ['"argv", "input"'],
        "ssrf_patterns": ['r"curl_easy_perform", r"send"'],
        "ssrf_evidence": ['"argv", "input"'],
        "redirect_patterns": ['r"Location:"'],
        "redirect_evidence": ['"argv", "input"'],
        "info_patterns": ['r"printf.*password", r"printf.*secret"'],
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
    "cpp": {
        "language": "C++",
        "class_name": "CPP",
        "command_patterns": ['r"system\\s*\\(", r"popen\\s*\\(", r"exec"'],
        "command_evidence": ['"argv", "input"'],
        "code_patterns": ['r"system\\s*\\("],
        "code_evidence": ['"argv", "input"'],
        "sql_patterns": ['r"mysql_query", r"sqlite3_exec"'],
        "sql_evidence": ['"argv", "input", "strcat", "+"'],
        "xss_patterns": ['r"cout\\s+<<", r"printf\\s*\\("],
        "xss_evidence": ['"argv", "input"'],
        "path_patterns": ['r"fstream", r"ifstream", r"ofstream"'],
        "path_evidence": ['"../", "..\\\\", "argv", "input"'],
        "crypto_patterns": ['r"MD5", r"SHA1", r"DES"'],
        "deserialize_patterns": ['r"unserialize"'],
        "deserialize_evidence": ['"argv", "input"'],
        "ssrf_patterns": ['r"curl_easy_perform", r"send"'],
        "ssrf_evidence": ['"argv", "input"'],
        "redirect_patterns": ['r"Location:"'],
        "redirect_evidence": ['"argv", "input"'],
        "info_patterns": ['r"cout.*password", r"cout.*secret"'],
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
    "fsharp": {
        "language": "F#",
        "class_name": "FSharp",
        "command_patterns": ['r"Process\\.Start", r"Shell"'],
        "command_evidence": ['"argv", "input"'],
        "code_patterns": ['r"eval"'],
        "code_evidence": ['"argv", "input"'],
        "sql_patterns": ['r"ExecuteReader", r"ExecuteNonQuery"'],
        "sql_evidence": ['"argv", "input", "+"'],
        "xss_patterns": ['r"printfn", r"printf"'],
        "xss_evidence": ['"argv", "input"'],
        "path_patterns": ['r"File\\.ReadAllText", r"File\\.OpenRead"'],
        "path_evidence": ['"../", "..\\\\", "argv", "input"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"JsonConvert\\.DeserializeObject"'],
        "deserialize_evidence": ['"argv", "input"'],
        "ssrf_patterns": ['r"HttpClient", r"WebRequest"'],
        "ssrf_evidence": ['"argv", "input"'],
        "redirect_patterns": ['r"Response\\.Redirect"'],
        "redirect_evidence": ['"argv", "input"'],
        "info_patterns": ['r"printfn.*password", r"printfn.*secret"'],
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("(*")',
    },
    "vbnet": {
        "language": "VB.NET",
        "class_name": "VBNet",
        "command_patterns": ['r"Process\\.Start", r"Shell"'],
        "command_evidence": ['"Request", "QueryString"'],
        "code_patterns": ['r"Eval"'],
        "code_evidence": ['"Request", "QueryString"'],
        "sql_patterns": ['r"ExecuteReader", r"ExecuteNonQuery"'],
        "sql_evidence": ['"Request", "QueryString", "&"'],
        "xss_patterns": ['r"Response\\.Write", r"Literal"'],
        "xss_evidence": ['"Request", "QueryString"'],
        "path_patterns": ['r"File\\.ReadAllText", r"File\\.OpenRead"'],
        "path_evidence": ['"../", "..\\\\", "Request", "QueryString"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"Deserialize"'],
        "deserialize_evidence": ['"Request", "QueryString"'],
        "ssrf_patterns": ['r"HttpWebRequest", r"WebClient"'],
        "ssrf_evidence": ['"Request", "QueryString"'],
        "redirect_patterns": ['r"Response\\.Redirect"'],
        "redirect_evidence": ['"Request", "QueryString"'],
        "info_patterns": ['r"Response\\.Write.*password", r"Response\\.Write.*secret"'],
        "comment_check": 'return stripped.startswith("\'")',
    },
    "groovy": {
        "language": "Groovy",
        "class_name": "Groovy",
        "command_patterns": ['r"execute\\s*\\(", r"ProcessBuilder"'],
        "command_evidence": ['"params", "request"'],
        "code_patterns": ['r"eval\\s*\\(", r"GroovyShell"'],
        "code_evidence": ['"params", "request"'],
        "sql_patterns": ['r"execute", r"sql"'],
        "sql_evidence": ['"params", "request", "+"'],
        "xss_patterns": ['r"println", r"markupBuilder"'],
        "xss_evidence": ['"params", "request"'],
        "path_patterns": ['r"new File\\(", r"FileReader"'],
        "path_evidence": ['"../", "..\\\\", "params", "request"'],
        "crypto_patterns": ['r"MD5", r"SHA1"'],
        "deserialize_patterns": ['r"ObjectInputStream", r"JsonSlurper"'],
        "deserialize_evidence": ['"params", "request"'],
        "ssrf_patterns": ['r"HttpBuilder", r"URL"'],
        "ssrf_evidence": ['"params", "request"'],
        "redirect_patterns": ['r"redirect"'],
        "redirect_evidence": ['"params", "request"'],
        "info_patterns": ['r"println.*password", r"println.*secret"'],
        "comment_check": 'return stripped.startswith("//") or stripped.startswith("/*")',
    },
}

def generate_analyzer(language_config: Dict) -> str:
    """Generate analyzer code for a language."""
    template = TEMPLATE

    # Replace placeholders
    replacements = {
        "{{LANGUAGE}}": language_config["language"],
        "{{CLASS_NAME}}": language_config["class_name"],
        "{{COMMAND_PATTERNS}}": language_config["command_patterns"],
        "{{COMMAND_EVIDENCE}}": language_config["command_evidence"],
        "{{CODE_PATTERNS}}": language_config["code_patterns"],
        "{{CODE_EVIDENCE}}": language_config["code_evidence"],
        "{{SQL_PATTERNS}}": language_config["sql_patterns"],
        "{{SQL_EVIDENCE}}": language_config["sql_evidence"],
        "{{XSS_PATTERNS}}": language_config["xss_patterns"],
        "{{XSS_EVIDENCE}}": language_config["xss_evidence"],
        "{{PATH_PATTERNS}}": language_config["path_patterns"],
        "{{PATH_EVIDENCE}}": language_config["path_evidence"],
        "{{CRYPTO_PATTERNS}}": language_config["crypto_patterns"],
        "{{DESERIALIZE_PATTERNS}}": language_config["deserialize_patterns"],
        "{{DESERIALIZE_EVIDENCE}}": language_config["deserialize_evidence"],
        "{{SSRF_PATTERNS}}": language_config["ssrf_patterns"],
        "{{SSRF_EVIDENCE}}": language_config["ssrf_evidence"],
        "{{REDIRECT_PATTERNS}}": language_config["redirect_patterns"],
        "{{REDIRECT_EVIDENCE}}": language_config["redirect_evidence"],
        "{{INFO_PATTERNS}}": language_config["info_patterns"],
        "{{COMMENT_CHECK}}": language_config["comment_check"],
    }

    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)

    return template

def main():
    """Generate all analyzers."""
    os.makedirs("valid8/language_support", exist_ok=True)

    for lang_key, config in LANGUAGES.items():
        filename = f"valid8/language_support/{lang_key}_analyzer.py"
        content = generate_analyzer(config)

        with open(filename, "w") as f:
            f.write(content)

        print(f"Generated {filename}")

if __name__ == "__main__":
    main()
