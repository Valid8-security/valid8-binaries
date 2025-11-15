"""API Security Vulnerability Detectors - 10+ CWEs"""
import re
from pathlib import Path
from typing import List
from valid8.scanner import Vulnerability, VulnerabilityDetector

class MissingRateLimitDetector(VulnerabilityDetector):
    """CWE-770: Allocation of Resources Without Limits"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@(route|api|endpoint|post|get)', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'rate[_-]?limit|throttle|ratelimit', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-770", severity="low", title="Missing Rate Limiting", description="API endpoint without rate limiting.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="low", category="api-security"))
        return vulnerabilities

class SSRFDetector(VulnerabilityDetector):
    """CWE-918: Server-Side Request Forgery"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [(r'requests\.get\(.*\+.*request|.*fetch\(.*\+.*user|.*urllib\.(urlopen|request)\(.*\+', "CWE-918", "high")]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(cwe="CWE-918", severity=severity, title="Server-Side Request Forgery", description="SSRF vulnerability detected.", file_path=str(file_path), line_number=i, code_snippet=line.strip(), confidence="medium", category="api-security"))
        return vulnerabilities

class IDORDetector(VulnerabilityDetector):
    """CWE-639: Authorization Bypass Through User-Controlled Key"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'/user/\$\{.*\}', "CWE-639", "high"),
            (r'/resource/\$\{.*\}', "CWE-639", "high"),
            (r'user_id.*param', "CWE-639", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="IDOR Vulnerability",
                        description="Insecure Direct Object Reference - user can access other users' data.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class MassAssignmentDetector(VulnerabilityDetector):
    """CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'update.*request\.body', "CWE-915", "high"),
            (r'user\.update\(.*params', "CWE-915", "high"),
            (r'object\.assign\(.*req', "CWE-915", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Mass Assignment",
                        description="Mass assignment vulnerability - all request parameters are assignable.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="api-security"
                    ))
        return vulnerabilities

class MissingAuthenticationAPIDetector(VulnerabilityDetector):
    """CWE-306: Missing Authentication for Critical Function"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@.*(post|put|delete|patch)', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'@.*auth|@.*login|jwt|token|session', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-306", severity="high", title="Missing Authentication",
                        description="API endpoint missing authentication requirement.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class CORSDetector(VulnerabilityDetector):
    """CWE-942: Permissive Cross-domain Policy with Untrusted Domains"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'Access-Control-Allow-Origin.*\*', "CWE-942", "medium"),
            (r'CORS.*allow.*all', "CWE-942", "medium"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Permissive CORS",
                        description="CORS policy allows all origins - potential security risk.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class SQLInjectionAPIDetector(VulnerabilityDetector):
    """CWE-89: SQL Injection in API"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'executeQuery\(.*\+.*request', "CWE-89", "critical"),
            (r'query\(.*\+.*params', "CWE-89", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="SQL Injection in API",
                        description="SQL injection in API endpoint.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="api-security"
                    ))
        return vulnerabilities

class CommandInjectionAPIDetector(VulnerabilityDetector):
    """CWE-78: Command Injection in API"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'exec\(.*\+.*request', "CWE-78", "critical"),
            (r'system\(.*\+.*params', "CWE-78", "critical"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Command Injection in API",
                        description="Command injection in API endpoint.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="api-security"
                    ))
        return vulnerabilities

class PathTraversalAPIDetector(VulnerabilityDetector):
    """CWE-22: Path Traversal in API"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'open\(.*\+.*request', "CWE-22", "high"),
            (r'file.*path.*params', "CWE-22", "high"),
            (r'\.\./.*request', "CWE-22", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe=cwe, severity=severity, title="Path Traversal in API",
                        description="Path traversal vulnerability in API endpoint.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="api-security"
                    ))
        return vulnerabilities

class MissingInputValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@.*(post|put)', line, re.IGNORECASE):
                context = '\n'.join(lines[i:min(len(lines), i+10)])
                if not re.search(r'validate|check|schema|joi|yup', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing Input Validation",
                        description="API endpoint missing input validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="api-security"
                    ))
        return vulnerabilities

class InsecureDirectObjectReferenceDetector(VulnerabilityDetector):
    """CWE-639 variant: Insecure Direct Object Reference"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = [
            (r'/api/user/\$\{id\}', "CWE-639", "high"),
            (r'/resource/\$\{.*\}', "CWE-639", "high"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if 'auth' not in context.lower() and 'check' not in context.lower():
                        vulnerabilities.append(Vulnerability(
                            cwe=cwe, severity=severity, title="Insecure Direct Object Reference",
                            description="Direct object reference without proper authorization check.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="api-security"
                        ))
        return vulnerabilities

class GraphQLDepthLimitDetector(VulnerabilityDetector):
    """CWE-770 variant: Missing GraphQL Depth Limit"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'graphql|graphQL', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if not re.search(r'depth.*limit|maxDepth|query.*depth', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-770", severity="medium", title="Missing GraphQL Depth Limit",
                        description="GraphQL endpoint without depth limiting - vulnerable to DoS.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="api-security"
                    ))
        return vulnerabilities

class APIVersioningDetector(VulnerabilityDetector):
    """CWE-710: Improper Adherence to Coding Standards - Missing API Versioning"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@app\.route|@GetMapping|@PostMapping|app\.get\(|app\.post\(', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'/v\d+|/api/v|version', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-710", severity="low", title="Missing API Versioning",
                        description="API endpoint without proper versioning.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="api-security"
                    ))
        return vulnerabilities

class MissingAPIContentTypeValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Missing Content-Type Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@PostMapping|@PutMapping|app\.post\(|app\.put\(', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'Content-Type|contentType|consumes|@Consumes', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing Content-Type Validation",
                        description="API endpoint without Content-Type validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class MissingAPIResponseValidationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Missing Response Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.|res\.send\(|return.*json', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'validate|schema|joi|yup|validateResponse', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="low", title="Missing API Response Validation",
                        description="API response without proper validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="api-security"
                    ))
        return vulnerabilities

class APITimeoutDetector(VulnerabilityDetector):
    """CWE-400: Uncontrolled Resource Consumption - Missing API Timeout"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'requests\.|fetch\(|axios\.', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'timeout|Timeout', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-400", severity="medium", title="Missing API Timeout",
                        description="API call without timeout configuration - potential DoS.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class MissingAPIKeyValidationDetector(VulnerabilityDetector):
    """CWE-284: Improper Access Control - Missing API Key Validation"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'api_key|apikey|x-api-key', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'validate|check|verify.*key', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-284", severity="high", title="Missing API Key Validation",
                        description="API key usage without proper validation.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class InsecureHTTPMethodDetector(VulnerabilityDetector):
    """CWE-650: Trusting HTTP Permission Methods on the Server Side"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@PutMapping|@PatchMapping|@DeleteMapping', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not re.search(r'@PreAuthorize|@Secured|security|auth', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-650", severity="high", title="Insecure HTTP Method",
                        description="Sensitive HTTP method without proper authorization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="high", category="api-security"
                    ))
        return vulnerabilities

class MissingAPILoggingDetector(VulnerabilityDetector):
    """CWE-778: Insufficient Logging - Missing API Request Logging"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestMapping|@GetMapping|@PostMapping|app\.(get|post)', line):
                context = '\n'.join(lines[max(0, i-15):min(len(lines), i+15)])
                if not re.search(r'logger\.|log\.|console\.log', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-778", severity="low", title="Missing API Request Logging",
                        description="API endpoint without request logging for security monitoring.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="low", category="api-security"
                    ))
        return vulnerabilities

class APIParameterInjectionDetector(VulnerabilityDetector):
    """CWE-88: Argument Injection or Modification"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@PathVariable|@RequestParam|req\.params', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if not re.search(r'sanitiz|escap|validat', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-88", severity="medium", title="API Parameter Injection",
                        description="API parameter used without sanitization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class MissingAPIErrorHandlingDetector(VulnerabilityDetector):
    """CWE-755: Improper Handling of Exceptional Conditions - Missing API Error Handling"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestMapping|@GetMapping|@PostMapping|app\.(get|post)', line):
                context = '\n'.join(lines[max(0, i):min(len(lines), i+20)])
                if not re.search(r'try:|catch|@ExceptionHandler|@ControllerAdvice', context):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-755", severity="medium", title="Missing API Error Handling",
                        description="API endpoint without proper error handling.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class APISensitiveDataExposureDetector(VulnerabilityDetector):
    """CWE-200: Information Disclosure - Sensitive Data in API Response"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        sensitive_patterns = [
            (r'password|Password', "password"),
            (r'token|Token', "token"),
            (r'secret|Secret', "secret"),
            (r'key|Key', "key"),
        ]
        for i, line in enumerate(lines, 1):
            if re.search(r'return.*json|@ResponseBody|res\.json\(', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                for pattern, data_type in sensitive_patterns:
                    if re.search(pattern, context, re.IGNORECASE):
                        vulnerabilities.append(Vulnerability(
                            cwe="CWE-200", severity="high", title="Sensitive Data in API Response",
                            description=f"API response may expose sensitive {data_type} data.",
                            file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                            confidence="medium", category="api-security"
                        ))
        return vulnerabilities

class MissingAPICORSHeadersDetector(VulnerabilityDetector):
    """CWE-346: Origin Validation Error - Missing CORS Headers"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@CrossOrigin|@RequestMapping|app\.|express\(\)', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if not re.search(r'Access-Control-Allow-Origin|origins|CORS', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-346", severity="medium", title="Missing CORS Configuration",
                        description="API without proper CORS configuration.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class APIRaceConditionDetector(VulnerabilityDetector):
    """CWE-362: Race Condition - Concurrent API Access"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'counter|balance|inventory|stock', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'@RequestMapping|@PostMapping|app\.post', context) and not re.search(r'synchronized|lock|@Transactional', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-362", severity="high", title="API Race Condition",
                        description="API endpoint with shared state but no synchronization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class MissingAPIInputSanitizationDetector(VulnerabilityDetector):
    """CWE-20: Improper Input Validation - Missing Input Sanitization"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestBody|@RequestParam|req\.body', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if not re.search(r'validat|sanitiz|escap|clean', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-20", severity="medium", title="Missing API Input Sanitization",
                        description="API input used without sanitization.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

class APIOverpostingDetector(VulnerabilityDetector):
    """CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - API Overposting"""
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestBody|req\.body', line):
                context = '\n'.join(lines[max(0, i-10):min(len(lines), i+10)])
                if re.search(r'User|Account|Profile', context) and not re.search(r'@JsonIgnore|exclude|bind', context, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-915", severity="high", title="API Overposting Vulnerability",
                        description="API accepts full object binding without field restrictions.",
                        file_path=str(file_path), line_number=i, code_snippet=line.strip(),
                        confidence="medium", category="api-security"
                    ))
        return vulnerabilities

def get_api_security_detectors():
    return [
        MissingRateLimitDetector(), SSRFDetector(), IDORDetector(), MassAssignmentDetector(),
        MissingAuthenticationAPIDetector(), CORSDetector(), SQLInjectionAPIDetector(),
        CommandInjectionAPIDetector(), PathTraversalAPIDetector(), MissingInputValidationDetector(),
        InsecureDirectObjectReferenceDetector(), GraphQLDepthLimitDetector(),
        APIVersioningDetector(), MissingAPIContentTypeValidationDetector(), MissingAPIResponseValidationDetector(),
        APITimeoutDetector(), MissingAPIKeyValidationDetector(), InsecureHTTPMethodDetector(),
        MissingAPILoggingDetector(), APIParameterInjectionDetector(), MissingAPIErrorHandlingDetector(),
        APISensitiveDataExposureDetector(), MissingAPICORSHeadersDetector(), APIRaceConditionDetector(),
        MissingAPIInputSanitizationDetector(), APIOverpostingDetector(),
    ]
    return [MissingRateLimitDetector(), SSRFDetector()]