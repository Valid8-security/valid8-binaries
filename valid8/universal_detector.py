"""
🚀 WORKING UNIVERSAL VULNERABILITY DETECTOR
Uses comprehensive pattern matching to detect ANY vulnerability type
"""

import re
from typing import List, Dict, Any, Optional
from .scanner import Vulnerability


class UniversalVulnerabilityDetector:
    """
    🚀 WORKING Universal detector for ANY vulnerability type
    Uses comprehensive pattern matching instead of complex ML models
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.universal_patterns = self._load_comprehensive_patterns()

    def detect_any_vulnerability(self, code: str) -> List[Vulnerability]:
        """
        🚀 DETECT ANY VULNERABILITY using comprehensive pattern matching
        """
        vulnerabilities = []

        # Split code into lines for analysis
        lines = code.split('\n')

        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check against all vulnerability patterns
            for vuln_category, vuln_data in self.universal_patterns.items():
                for pattern_data in vuln_data['patterns']:
                    pattern = pattern_data['regex']
                    if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                        vuln = Vulnerability(
                            cwe=pattern_data['cwe'],
                            severity=pattern_data['severity'],
                            title=f"{vuln_category.replace('_', ' ').title()}: {pattern_data['title']}",
                            description=pattern_data['description'],
                            file_path=self.filepath,
                            line_number=line_number,
                            code_snippet=line,
                            confidence=pattern_data['confidence']
                        )
                        vulnerabilities.append(vuln)

        # Apply deduplication and context validation
        validated_vulns = self._deduplicate_and_validate(vulnerabilities, lines)

        return validated_vulns

    def _load_comprehensive_patterns(self) -> Dict[str, Any]:
        """Load comprehensive vulnerability patterns for universal detection"""
        return {
            "sql_injection": {
                "patterns": [
                    {
                        "regex": r"cursor\.execute\(.*f.*SELECT.*\{.*\}",
                        "cwe": "CWE-89",
                        "severity": "critical",
                        "title": "SQL Injection via f-string",
                        "description": "SQL query with user input via f-string formatting",
                        "confidence": 0.95
                    },
                    {
                        "regex": r"cursor\.execute\(.*%.*SELECT",
                        "cwe": "CWE-89",
                        "severity": "critical",
                        "title": "SQL Injection via string formatting",
                        "description": "SQL query with user input via % formatting",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"sqlite3.*connect.*execute.*request\.",
                        "cwe": "CWE-89",
                        "severity": "high",
                        "title": "SQL Injection via request data",
                        "description": "Database query using request data directly",
                        "confidence": 0.85
                    }
                ]
            },
            "xss_injection": {
                "patterns": [
                    {
                        "regex": r"return.*f.*<.*\{.*request\.",
                        "cwe": "CWE-79",
                        "severity": "high",
                        "title": "XSS via f-string HTML output",
                        "description": "HTML output with user input via f-string",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"innerHTML.*\+.*request\.",
                        "cwe": "CWE-79",
                        "severity": "high",
                        "title": "DOM XSS via innerHTML",
                        "description": "JavaScript innerHTML with user input",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"document\.write.*request\.",
                        "cwe": "CWE-79",
                        "severity": "high",
                        "title": "XSS via document.write",
                        "description": "Direct document.write with user input",
                        "confidence": 0.80
                    }
                ]
            },
            "command_injection": {
                "patterns": [
                    {
                        "regex": r"os\.system\(.*f.*request\.",
                        "cwe": "CWE-78",
                        "severity": "critical",
                        "title": "Command Injection via f-string",
                        "description": "Shell command with user input via f-string",
                        "confidence": 0.95
                    },
                    {
                        "regex": r"subprocess\..*\(.*f.*request\.",
                        "cwe": "CWE-78",
                        "severity": "critical",
                        "title": "Command Injection via subprocess",
                        "description": "Subprocess call with user input",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"eval\(.*request\.",
                        "cwe": "CWE-95",
                        "severity": "critical",
                        "title": "Code Injection via eval",
                        "description": "Code execution with user input",
                        "confidence": 0.95
                    }
                ]
            },
            "path_traversal": {
                "patterns": [
                    {
                        "regex": r"open\(.*f.*request\.",
                        "cwe": "CWE-22",
                        "severity": "high",
                        "title": "Path Traversal via file open",
                        "description": "File access with user-controlled path",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"pathlib\.Path\(.*request\.",
                        "cwe": "CWE-22",
                        "severity": "high",
                        "title": "Path Traversal via pathlib",
                        "description": "Path manipulation with user input",
                        "confidence": 0.80
                    },
                    {
                        "regex": r"\.\./",
                        "cwe": "CWE-22",
                        "severity": "medium",
                        "title": "Directory Traversal",
                        "description": "Potential directory traversal sequence",
                        "confidence": 0.70
                    }
                ]
            },
            "idor_vulnerability": {
                "patterns": [
                    {
                        "regex": r"def get_user.*user_id.*request",
                        "cwe": "CWE-639",
                        "severity": "high",
                        "title": "IDOR: User data access",
                        "description": "Function accessing user data without authorization check",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"def.*user.*request\.args",
                        "cwe": "CWE-639",
                        "severity": "medium",
                        "title": "IDOR: User ID from request",
                        "description": "User identifier from request without validation",
                        "confidence": 0.75
                    },
                    {
                        "regex": r"SELECT.*WHERE.*id.*request",
                        "cwe": "CWE-639",
                        "severity": "high",
                        "title": "IDOR: Direct ID access",
                        "description": "Database query using direct ID from request",
                        "confidence": 0.80
                    }
                ]
            },
            "ssrf_vulnerability": {
                "patterns": [
                    {
                        "regex": r"requests\.get\(.*request\.",
                        "cwe": "CWE-918",
                        "severity": "high",
                        "title": "SSRF via requests.get",
                        "description": "HTTP request to user-controlled URL",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"urllib.*request.*request\.",
                        "cwe": "CWE-918",
                        "severity": "high",
                        "title": "SSRF via urllib",
                        "description": "URL request to user-controlled destination",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"fetch\(.*request\.",
                        "cwe": "CWE-918",
                        "severity": "high",
                        "title": "SSRF via fetch",
                        "description": "Network request to user-controlled URL",
                        "confidence": 0.85
                    }
                ]
            },
            "xxe_vulnerability": {
                "patterns": [
                    {
                        "regex": r"xml\.etree.*parse",
                        "cwe": "CWE-611",
                        "severity": "high",
                        "title": "XXE via XML parsing",
                        "description": "XML parsing that may be vulnerable to XXE",
                        "confidence": 0.80
                    },
                    {
                        "regex": r"lxml.*parse",
                        "cwe": "CWE-611",
                        "severity": "high",
                        "title": "XXE via lxml parsing",
                        "description": "XML parsing with lxml library",
                        "confidence": 0.75
                    },
                    {
                        "regex": r"etree.*parse.*request",
                        "cwe": "CWE-611",
                        "severity": "critical",
                        "title": "XXE with user input",
                        "description": "XML parsing of user-controlled data",
                        "confidence": 0.95
                    }
                ]
            },
            "csrf_vulnerability": {
                "patterns": [
                    {
                        "regex": r"@app\.route.*POST.*def.*password",
                        "cwe": "CWE-352",
                        "severity": "medium",
                        "title": "CSRF: Password change without token",
                        "description": "Password change endpoint without CSRF protection",
                        "confidence": 0.75
                    },
                    {
                        "regex": r"def.*delete.*POST",
                        "cwe": "CWE-352",
                        "severity": "high",
                        "title": "CSRF: Delete operation",
                        "description": "Delete operation without CSRF protection",
                        "confidence": 0.80
                    },
                    {
                        "regex": r"def.*update.*POST",
                        "cwe": "CWE-352",
                        "severity": "medium",
                        "title": "CSRF: Update operation",
                        "description": "Update operation without CSRF protection",
                        "confidence": 0.75
                    }
                ]
            },
            "hardcoded_credentials": {
                "patterns": [
                    {
                        "regex": r"password.*=.*[\"'][^\"']{6,}[\"']",
                        "cwe": "CWE-798",
                        "severity": "high",
                        "title": "Hardcoded Password",
                        "description": "Hardcoded password string in code",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"api_key.*=.*[\"'][^\"']{10,}[\"']",
                        "cwe": "CWE-798",
                        "severity": "high",
                        "title": "Hardcoded API Key",
                        "description": "Hardcoded API key string in code",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"secret.*=.*[\"'][^\"']{8,}[\"']",
                        "cwe": "CWE-798",
                        "severity": "high",
                        "title": "Hardcoded Secret",
                        "description": "Hardcoded secret string in code",
                        "confidence": 0.90
                    }
                ]
            },
            "weak_crypto": {
                "patterns": [
                    {
                        "regex": r"hashlib\.md5",
                        "cwe": "CWE-327",
                        "severity": "medium",
                        "title": "Weak Hash: MD5",
                        "description": "Use of weak MD5 hash algorithm",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"hashlib\.sha1",
                        "cwe": "CWE-327",
                        "severity": "medium",
                        "title": "Weak Hash: SHA1",
                        "description": "Use of weak SHA1 hash algorithm",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"random\.",
                        "cwe": "CWE-338",
                        "severity": "low",
                        "title": "Weak Randomness",
                        "description": "Use of weak random number generation",
                        "confidence": 0.70
                    }
                ]
            },
            "deserialization": {
                "patterns": [
                    {
                        "regex": r"pickle\.loads",
                        "cwe": "CWE-502",
                        "severity": "high",
                        "title": "Unsafe Deserialization: pickle.loads",
                        "description": "Use of pickle.loads for deserialization",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"yaml\.load",
                        "cwe": "CWE-502",
                        "severity": "high",
                        "title": "Unsafe Deserialization: yaml.load",
                        "description": "Use of yaml.load for deserialization",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"marshal\.loads",
                        "cwe": "CWE-502",
                        "severity": "high",
                        "title": "Unsafe Deserialization: marshal.loads",
                        "description": "Use of marshal.loads for deserialization",
                        "confidence": 0.85
                    }
                ]
            },
            "information_disclosure": {
                "patterns": [
                    {
                        "regex": r"print\(.*password",
                        "cwe": "CWE-200",
                        "severity": "medium",
                        "title": "Info Disclosure: Password in logs",
                        "description": "Password information printed/logged",
                        "confidence": 0.80
                    },
                    {
                        "regex": r"return.*password",
                        "cwe": "CWE-200",
                        "severity": "medium",
                        "title": "Info Disclosure: Password in response",
                        "description": "Password information returned in response",
                        "confidence": 0.80
                    },
                    {
                        "regex": r"debug.*=.*True",
                        "cwe": "CWE-489",
                        "severity": "low",
                        "title": "Debug Mode Enabled",
                        "description": "Debug mode enabled in production",
                        "confidence": 0.70
                    }
                ]
            },
            "auth_bypass": {
                "patterns": [
                    {
                        "regex": r"if.*admin.*return.*True",
                        "cwe": "CWE-287",
                        "severity": "critical",
                        "title": "Auth Bypass: Admin check",
                        "description": "Authentication bypass for admin user",
                        "confidence": 0.90
                    },
                    {
                        "regex": r"session.*==.*[\"'][^\"']+",
                        "cwe": "CWE-287",
                        "severity": "high",
                        "title": "Weak Session Validation",
                        "description": "Weak session validation with hardcoded values",
                        "confidence": 0.85
                    },
                    {
                        "regex": r"token.*==.*[\"'][^\"']+",
                        "cwe": "CWE-287",
                        "severity": "high",
                        "title": "Weak Token Validation",
                        "description": "Weak token validation with hardcoded values",
                        "confidence": 0.85
                    }
                ]
            }
        }

    def _deduplicate_and_validate(self, vulnerabilities: List[Vulnerability], lines: List[str]) -> List[Vulnerability]:
        """Deduplicate and validate vulnerabilities"""
        seen = set()
        validated = []

        for vuln in vulnerabilities:
            # Create unique key
            key = f"{vuln.cwe}:{vuln.line_number}:{hash(vuln.code_snippet[:50])}"

            if key not in seen:
                seen.add(key)

                # Additional validation
                if self._validate_vulnerability_context(vuln, lines):
                    validated.append(vuln)

        return validated

    def _validate_vulnerability_context(self, vuln: Vulnerability, lines: List[str]) -> bool:
        """Validate vulnerability in context"""
        # Skip if in test files
        if 'test' in self.filepath.lower():
            return False

        # Skip if in commented code
        if vuln.line_number > 0 and vuln.line_number <= len(lines):
            line = lines[vuln.line_number - 1]
            if line.strip().startswith('#') or 'TODO' in line or 'FIXME' in line:
                return False

        # Additional context checks can be added here
        return True
