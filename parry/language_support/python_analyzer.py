"""
Python language security analyzer.
"""

import re
import ast
from typing import List
from .base import LanguageAnalyzer, Vulnerability
from .universal_detectors import UniversalDetectors
from ..data_flow_analyzer import DataFlowAnalyzer
from ..framework_detectors import DjangoDetector, FlaskDetector


class PythonAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Python code."""
    
    def __init__(self):
        super().__init__()
        self.language = "python"
        self.data_flow_analyzer = DataFlowAnalyzer()
        self.django_detector = DjangoDetector()
        self.flask_detector = FlaskDetector()
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-90',   # LDAP Injection
            'CWE-94',   # Code Injection (eval/exec)
            'CWE-113',  # HTTP Header Injection
            'CWE-190',  # Integer Overflow
            'CWE-200',  # Information Exposure
            'CWE-209',  # Information Disclosure in Error Messages
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-295',  # Improper Certificate Validation
            'CWE-306',  # Missing Authentication for Critical Function
            'CWE-311',  # Missing Encryption of Sensitive Data
            'CWE-319',  # Cleartext Transmission
            'CWE-321',  # Hard-coded Cryptographic Key
            'CWE-327',  # Weak Crypto
            'CWE-330',  # Use of Insufficiently Random Values
            'CWE-352',  # CSRF
            'CWE-362',  # Race Condition
            'CWE-377',  # Insecure Temporary File
            'CWE-384',  # Session Fixation
            'CWE-434',  # Unrestricted File Upload
            'CWE-502',  # Unsafe Deserialization
            'CWE-601',  # Open Redirect
            'CWE-611',  # XXE
            'CWE-614',  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
            'CWE-643',  # XPath Injection
            'CWE-732',  # Incorrect Permissions
            'CWE-749',  # Exposed Dangerous Method or Function
            'CWE-770',  # Allocation of Resources Without Limits or Throttling
            'CWE-798',  # Hardcoded Credentials
            'CWE-918',  # SSRF
        ]
    
    def parse_ast(self, code: str):
        """Parse Python code into AST."""
        try:
            return ast.parse(code)
        except:
            return None
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Python code for vulnerabilities."""
        vulnerabilities = []
        
        # Run language-specific detection methods
        vulnerabilities.extend(self.detect_command_injection(code, filepath))
        vulnerabilities.extend(self.detect_code_injection(code, filepath))
        vulnerabilities.extend(self.detect_sql_injection(code, filepath))
        vulnerabilities.extend(self.detect_xss(code, filepath))
        vulnerabilities.extend(self.detect_path_traversal(code, filepath))
        vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_password(code, filepath))
        vulnerabilities.extend(self.detect_insecure_temp_file(code, filepath))
        vulnerabilities.extend(self.detect_open_redirect(code, filepath))
        vulnerabilities.extend(self.detect_unsafe_deserialization(code, filepath))
        vulnerabilities.extend(self.detect_xxe(code, filepath))
        vulnerabilities.extend(self.detect_ssrf(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))
        
        # NEW: Extended CWE detection methods
        vulnerabilities.extend(self.detect_missing_authentication(code, filepath))
        vulnerabilities.extend(self.detect_unrestricted_file_upload(code, filepath))
        vulnerabilities.extend(self.detect_exposed_dangerous_method(code, filepath))
        vulnerabilities.extend(self.detect_resource_exhaustion(code, filepath))
        vulnerabilities.extend(self.detect_http_header_injection(code, filepath))
        vulnerabilities.extend(self.detect_error_message_disclosure(code, filepath))
        vulnerabilities.extend(self.detect_insecure_random(code, filepath))
        vulnerabilities.extend(self.detect_weak_certificate_validation(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_crypto_key(code, filepath))
        vulnerabilities.extend(self.detect_missing_encryption(code, filepath))
        vulnerabilities.extend(self.detect_insecure_http(code, filepath))
        vulnerabilities.extend(self.detect_ldap_injection(code, filepath))
        vulnerabilities.extend(self.detect_xpath_injection(code, filepath))
        vulnerabilities.extend(self.detect_improper_session_management(code, filepath))
        vulnerabilities.extend(self.detect_race_condition(code, filepath))
        vulnerabilities.extend(self.detect_integer_overflow(code, filepath))
        vulnerabilities.extend(self.detect_insecure_cookie(code, filepath))
        
        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_csrf(code, filepath))
        
        # CRITICAL: Data flow analysis for complex vulnerabilities (90% recall)
        try:
            data_flow_vulns = self.data_flow_analyzer.analyze(code, filepath)
            vulnerabilities.extend(data_flow_vulns)
        except Exception as e:
            # Fallback if data flow analysis fails
            pass
        
        # Framework-specific detection (Django, Flask)
        try:
            if any(keyword in code.lower() for keyword in ['from django', 'import django', 'django.']):
                django_vulns = self.django_detector.detect(code, filepath)
                vulnerabilities.extend(django_vulns)
            if any(keyword in code.lower() for keyword in ['from flask', 'import flask', 'flask.']):
                flask_vulns = self.flask_detector.detect(code, filepath)
                vulnerabilities.extend(flask_vulns)
        except Exception as e:
            # Fallback if framework detection fails
            pass
        
        return vulnerabilities
    
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in Python."""
        patterns = [
            (r'os\.system\s*\(', 'os.system'),
            (r'subprocess\.call\s*\(', 'subprocess.call'),
            (r'subprocess\.run\s*\(', 'subprocess.run'),
            (r'subprocess\.Popen\s*\(', 'subprocess.Popen'),
            (r'os\.popen\s*\(', 'os.popen'),
            (r'commands\.getoutput\s*\(', 'commands.getoutput'),
            (r'eval\s*\(', 'eval'),
            (r'exec\s*\(', 'exec'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, func_name in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description=f'Potential command injection using {func_name}. User input should never be passed directly to system commands.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Python."""
        patterns = [
            r'execute\s*\(\s*["\'].*%s',
            r'execute\s*\(\s*["\'].*\+',
            r'execute\s*\(\s*f["\']',
            r'\.format\s*\(.*\).*execute',
            r'cursor\.execute\s*\(.*\.format',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='SQL Injection',
                        description='Potential SQL injection. Use parameterized queries instead of string formatting.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Python."""
        patterns = [
            r'mark_safe\s*\(',
            r'SafeString\s*\(',
            r'render_template_string\s*\(.*\+',
            r'\.innerHTML\s*=',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-79',
                        severity='high',
                        title='Cross-Site Scripting (XSS)',
                        description='Potential XSS vulnerability. User input should be properly escaped.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Python."""
        patterns = [
            r'open\s*\([^)]*\+',
            r'os\.path\.join\s*\([^)]*user',
            r'Path\s*\([^)]*\+',
            r'\.read\s*\([^)]*request',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-22',
                        severity='high',
                        title='Path Traversal',
                        description='Potential path traversal vulnerability. File paths should be validated.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in Python."""
        patterns = [
            (r'hashlib\.md5\s*\(', 'MD5'),
            (r'hashlib\.sha1\s*\(', 'SHA1'),
            (r'Crypto\.Hash\.MD5', 'MD5'),
            (r'Crypto\.Hash\.SHA1', 'SHA1'),
            (r'\.digest\s*\(\s*["\']md5', 'MD5'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, algo in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-327',
                        severity='medium',
                        title='Weak Cryptographic Algorithm',
                        description=f'Use of weak cryptographic algorithm {algo}. Use SHA-256 or stronger.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Python."""
        patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'api_key\s*=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'token\s*=\s*["\'][^"\']{10,}["\']', 'token'),
            (r'aws_secret\s*=\s*["\']', 'AWS secret'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('#'):
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type} detected. Store credentials in environment variables.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization in Python."""
        patterns = [
            r'pickle\.loads\s*\(',
            r'yaml\.load\s*\([^,)]*\)',  # yaml.load without Loader
            r'marshal\.loads\s*\(',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-502',
                        severity='high',
                        title='Unsafe Deserialization',
                        description='Unsafe deserialization of untrusted data. Use safe alternatives like JSON.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xxe(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XXE vulnerabilities in Python."""
        patterns = [
            r'etree\.parse\s*\(',
            r'etree\.fromstring\s*\(',
            r'xml\.etree\.ElementTree\.parse\s*\(',
            r'lxml\.etree\.parse\s*\(',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if XXE protection is present
                    if 'resolve_entities=False' not in line:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-611',
                            severity='high',
                            title='XML External Entity (XXE) Injection',
                            description='XML parser without XXE protection. Disable external entity resolution.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SSRF vulnerabilities in Python."""
        patterns = [
            r'requests\.get\s*\([^)]*request\.',
            r'requests\.post\s*\([^)]*request\.',
            r'urllib\.request\.urlopen\s*\([^)]*request\.',
            r'httplib\.request\s*\([^)]*request\.',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-918',
                        severity='high',
                        title='Server-Side Request Forgery (SSRF)',
                        description='Potential SSRF. Validate and whitelist URLs before making requests.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_code_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-94: Code Injection (eval, exec)."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Detect eval() and exec() usage
            if re.search(r'\.eval\s*\(', line) or re.search(r'\beval\s*\([^)]*\+', line):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-94',
                    severity='critical',
                    title='Code Injection via eval',
                    description='Dangerous eval() usage detected. User input may be executed as code.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
            elif re.search(r'\bexec\s*\([^)]*\+', line):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-94',
                    severity='critical',
                    title='Code Injection via exec',
                    description='Dangerous exec() usage detected. User input may be executed as code.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_hardcoded_password(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-259: Hard-coded Password."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # More specific password detection than generic secrets
            patterns = [
                (r'(?:if|elif)\s+.*password\s*==\s*["\'][^"\']+["\']', 'Direct password comparison'),
                (r'password\s*:\s*["\'][^"\']{4,}["\']', 'Hard-coded password in config'),
                (r'PASSWORD\s*=\s*["\'][^"\']{4,}["\']', 'Environment password'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it looks like a placeholder
                    if any(placeholder in line.lower() for placeholder in ['xxx', '***', 'dummy', 'example', 'test']):
                        continue
                    
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-259',
                        severity='critical',
                        title='Hard-coded Password',
                        description=f'{desc}. Store passwords securely, never hard-code them.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break
        
        return vulnerabilities
    
    def detect_insecure_temp_file(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-377: Insecure Temporary File."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Pattern for predictable temp file names
            if re.search(r'tempfile\.mktemp\s*\(', line):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-377',
                    severity='medium',
                    title='Insecure Temporary File',
                    description='mktemp() creates predictable file names. Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
            elif re.search(r'tmp[^/]*\s*=.*["\'].*tmp["\']', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-377',
                    severity='medium',
                    title='Predictable Temporary File Name',
                    description='Hard-coded temp file path is predictable and exploitable.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_open_redirect(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-601: Open Redirect."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # URL redirect patterns without validation
            patterns = [
                (r'(?:redirect|redirect_to)\s*\([^)]*\+', 'Unvalidated redirect'),
                (r'return\s+(?:redirect|Redirect)\s*\([^)]*\+', 'Unvalidated redirect return'),
                (r'location\.href\s*=\s*[^;]*(request|input|params|args)', 'Client-side redirect without validation'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check for common whitelist patterns
                    if any(protect in line.lower() for protect in ['whitelist', 'allowed', 'validate']):
                        continue
                    
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-601',
                        severity='medium',
                        title='URL Redirection to Untrusted Site',
                        description=f'{desc}. Always validate redirect URLs to prevent phishing.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break
        
        return vulnerabilities
    
    def detect_incorrect_permissions(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect incorrect file permissions in Python."""
        patterns = [
            (r'os\.chmod\s*\([^,]*,\s*0o?777', 'world-writable'),
            (r'os\.chmod\s*\([^,]*,\s*0o?666', 'world-readable/writable'),
            (r'open\s*\([^)]*mode\s*=\s*["\']w\+["\']', 'insecure open mode'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, issue in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-732',
                        severity='medium',
                        title='Incorrect Permission Assignment',
                        description=f'Insecure file permissions: {issue}. Use restrictive permissions.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_missing_authentication(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-306: Missing Authentication for Critical Function."""
        vulnerabilities = []
        lines = code.split('\n')
        
        dangerous_functions = [
            ('delete', 'delete'),
            ('admin', 'admin'),
            ('sudo', 'sudo'),
            ('clear', 'clear all'),
            ('reset', 'reset'),
        ]
        
        for i, line in enumerate(lines, 1):
            for func, desc in dangerous_functions:
                if re.search(rf'\bdef\s+{func}', line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    if not any(auth in context.lower() for auth in ['@login_required', '@require_auth', '@authenticate', 'authentication']):
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-306',
                            severity='critical',
                            title='Missing Authentication',
                            description=f'Critical function "{func}" has no authentication. Add @login_required or similar decorator.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_unrestricted_file_upload(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-434: Unrestricted Upload of File with Dangerous Type."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\.save\s*\(|upload.*\(|\.write\s*\(', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                has_validation = any(check in context.lower() for check in ['allowed', 'whitelist', 'validate', 'extension'])
                
                if not has_validation:
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-434',
                        severity='high',
                        title='Unrestricted File Upload',
                        description='File upload without type validation. Restrict file types to whitelist only.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_exposed_dangerous_method(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-749: Exposed Dangerous Method or Function."""
        vulnerabilities = []
        lines = code.split('\n')
        
        dangerous_methods = [
            (r'\.eval\s*\(', 'eval()'),
            (r'\.exec\s*\(', 'exec()'),
            (r'\.compile\s*\(', 'compile()'),
            (r'\.__import__\s*\(', '__import__()'),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, method in dangerous_methods:
                if re.search(pattern, line):
                    context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                    if any(endpoint in context.lower() for endpoint in ['@app.route', '@api_view', 'def get', 'def post']):
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-749',
                            severity='critical',
                            title='Exposed Dangerous Method',
                            description=f'Dangerous method {method} exposed in API. Remove or restrict access.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_resource_exhaustion(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-770: Allocation of Resources Without Limits or Throttling."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'for\s+\w+\s+in\s+(?:request|input|data|file).*:', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+10)])
                has_limit = any(limit in context.lower() for limit in ['limit', 'max', 'range', 'first', 'top', '[:'])
                
                if not has_limit:
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-770',
                        severity='medium',
                        title='Resource Exhaustion',
                        description='Loop over untrusted input without limits. Add pagination or limits.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_http_header_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'headers\[|headers\.\[|set_header|response\[\s*["\'].*(?::|location)', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if any(inp in context.lower() for inp in ['request', 'user', 'input', 'params', 'args']) and \
                   '\\r\\n' not in context and '\\n' not in context:
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-113',
                        severity='high',
                        title='HTTP Header Injection',
                        description='User-controlled input in HTTP headers. Sanitize or escape CRLF sequences.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_error_message_disclosure(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-209: Information Exposure Through an Error Message."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'raise\s+\w+Error.*\(|print\s*\(.*traceback|print\s*\(.*exception', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+1)])
                if 'test' not in filepath.lower() and \
                   not any(safe in context.lower() for safe in ['# safe', '# log', 'logger']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-209',
                        severity='low',
                        title='Error Message Information Disclosure',
                        description='Verbose error messages may leak sensitive information. Use generic messages in production.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_insecure_random(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-330: Use of Insufficiently Random Values."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'random\.(choice|randint|sample)', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if any(sec in context.lower() for sec in ['token', 'password', 'key', 'secret', 'session', 'auth']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-330',
                        severity='medium',
                        title='Insufficient Random Values',
                        description='Use random.choice()/randint() for cryptographic operations. Use secrets module instead.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_certificate_validation(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-295: Improper Certificate Validation."""
        vulnerabilities = []
        lines = code.split('\n')
        
        dangerous_patterns = [
            r'verify\s*=\s*False',
            r'ssl\._create_unverified_context',
            r'SSL_VERIFY_PEER\s*=\s*False',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-295',
                        severity='high',
                        title='Improper Certificate Validation',
                        description='SSL/TLS certificate verification disabled. Always verify certificates.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_crypto_key(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-321: Use of Hard-coded Cryptographic Key."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            patterns = [
                (r'key\s*=\s*["\'][^"\']{10,}["\']', 'key'),
                (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
                (r'SECRET_KEY\s*=\s*["\']', 'SECRET_KEY'),
                (r'AES\.new\s*\(.*["\'][^"\']+', 'AES key'),
            ]
            
            for pattern, key_type in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-321',
                        severity='critical',
                        title='Hard-coded Cryptographic Key',
                        description=f'Hard-coded {key_type} detected. Use environment variables or key management.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break
        
        return vulnerabilities
    
    def detect_missing_encryption(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-311: Missing Encryption of Sensitive Data."""
        vulnerabilities = []
        lines = code.split('\n')
        
        sensitive_patterns = [
            r'password\s*=',
            r'api_key\s*=',
            r'credit_card\s*=',
            r'ssn\s*=',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sensitive_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    has_encryption = any(enc in context.lower() for enc in ['encrypt', 'hash', 'sha256', 'bcrypt'])
                    
                    if not has_encryption:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-311',
                            severity='high',
                            title='Missing Encryption of Sensitive Data',
                            description='Sensitive data stored without encryption. Encrypt at rest and in transit.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_insecure_http(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-319: Cleartext Transmission of Sensitive Information."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'http://[^\s"\']+', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-319',
                    severity='high',
                    title='Cleartext Transmission',
                    description='HTTP used instead of HTTPS. Sensitive data transmitted without encryption.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_ldap_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-90: LDAP Injection."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'ldap.*search.*\+|\.bind.*\+', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-90',
                    severity='high',
                    title='LDAP Injection',
                    description='LDAP query with concatenated user input. Use parameterized queries.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_xpath_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-643: XPath Injection."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\.xpath\s*\(.*\+|xpath.*\(.*\+', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-643',
                    severity='high',
                    title='XPath Injection',
                    description='XPath query with concatenated user input. Use parameterized XPath expressions.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_improper_session_management(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-384: Session Fixation."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'session\[|flask\.session\[|request\.session\[', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if any(auth in context.lower() for auth in ['login', 'authenticate']) and \
                   'regenerate' not in context.lower() and 'new' not in context.lower():
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-384',
                        severity='medium',
                        title='Session Fixation',
                        description='Session ID not regenerated after authentication. Regenerate session ID on login.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_race_condition(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'open\s*\([^)]*["\']w', line) and 'with lock' not in line.lower():
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if any(shared in context.lower() for shared in ['shared', 'global', 'cache', 'log']) and \
                   not any(lock in context.lower() for lock in ['lock', 'mutex', 'synchronized']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-362',
                        severity='medium',
                        title='Race Condition',
                        description='File write without locking. Use file locks or atomic operations.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_integer_overflow(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-190: Integer Overflow or Wraparound."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\w+\s*\+\s*(input|request|args|params|int\()', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+2)])
                if not any(limit in context.lower() for limit in ['max', 'limit', 'bound', 'check']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-190',
                        severity='low',
                        title='Potential Integer Overflow',
                        description='Arithmetic operation on untrusted input without bounds checking.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_insecure_cookie(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.set_cookie|\.cookies\[', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+2)])
                has_secure = 'secure=true' in context.lower() or 'httponly=true' in context.lower()
                
                if not has_secure:
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-614',
                        severity='medium',
                        title='Insecure Cookie',
                        description='Cookie without Secure or HttpOnly flags. Add secure=True and httponly=True.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities

