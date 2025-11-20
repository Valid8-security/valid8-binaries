"""
Java language security analyzer.
"""

import re
from typing import List
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


class JavaAnalyzer(LanguageAnalyzer, UniversalDetectors):
    """Security analyzer for Java code."""
    
    def __init__(self):
        super().__init__()
        self.language = "java"
    
    def get_supported_cwes(self) -> List[str]:
        """Get supported CWE types."""
        return [
            'CWE-20',   # Improper Input Validation
            'CWE-22',   # Path Traversal
            'CWE-78',   # Command Injection
            'CWE-79',   # XSS
            'CWE-89',   # SQL Injection
            'CWE-90',   # LDAP Injection
            'CWE-113',  # HTTP Header Injection
            'CWE-190',  # Integer Overflow
            'CWE-200',  # Information Exposure
            'CWE-209',  # Information Disclosure
            'CWE-259',  # Hard-coded Password
            'CWE-287',  # Improper Authentication
            'CWE-295',  # Improper Certificate Validation
            'CWE-311',  # Missing Encryption
            'CWE-319',  # Cleartext Transmission
            'CWE-321',  # Hard-coded Cryptographic Key
            'CWE-327',  # Weak Crypto
            'CWE-330',  # Weak Random
            'CWE-352',  # CSRF
            'CWE-362',  # Race Condition
            'CWE-384',  # Session Fixation
            'CWE-470',  # Externally-Controlled Class Selection
            'CWE-476',  # NULL Pointer Dereference
            'CWE-502',  # Unsafe Deserialization
            'CWE-611',  # XXE
            'CWE-643',  # XPath Injection
            'CWE-732',  # Incorrect Permissions
            'CWE-798',  # Hardcoded Credentials
            'CWE-918',  # SSRF
        ]
    
    def parse_ast(self, code: str):
        """Parse Java code into AST."""
        try:
            import javalang
            return javalang.parse.parse(code)
        except:
            return None
    
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze Java code for vulnerabilities."""
        vulnerabilities = []
        
        # Use AST-based detection if available (more accurate)
        ast_tree = self.parse_ast(code)
        
        if ast_tree:
            # AST-based detection
            vulnerabilities.extend(self.detect_with_ast(ast_tree, code, filepath))
        else:
            # Fallback to regex patterns
            vulnerabilities.extend(self.detect_command_injection(code, filepath))
            vulnerabilities.extend(self.detect_sql_injection(code, filepath))
            vulnerabilities.extend(self.detect_xss(code, filepath))
            vulnerabilities.extend(self.detect_path_traversal(code, filepath))
            vulnerabilities.extend(self.detect_weak_crypto(code, filepath))
            vulnerabilities.extend(self.detect_hardcoded_secrets(code, filepath))
            vulnerabilities.extend(self.detect_unsafe_deserialization(code, filepath))
            vulnerabilities.extend(self.detect_xxe(code, filepath))
            vulnerabilities.extend(self.detect_ldap_injection(code, filepath))
            vulnerabilities.extend(self.detect_xpath_injection(code, filepath))
            vulnerabilities.extend(self.detect_weak_random(code, filepath))
            vulnerabilities.extend(self.detect_ssrf(code, filepath))
        
        # NEW: Extended CWE detection methods
        vulnerabilities.extend(self.detect_missing_encryption_java(code, filepath))
        vulnerabilities.extend(self.detect_weak_certificate_validation_java(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_crypto_key_java(code, filepath))
        vulnerabilities.extend(self.detect_insecure_http_java(code, filepath))
        vulnerabilities.extend(self.detect_error_message_disclosure_java(code, filepath))
        vulnerabilities.extend(self.detect_improper_session_management_java(code, filepath))
        vulnerabilities.extend(self.detect_http_header_injection_java(code, filepath))
        vulnerabilities.extend(self.detect_race_condition_java(code, filepath))
        vulnerabilities.extend(self.detect_integer_overflow_java(code, filepath))
        
        # Run universal detection methods
        vulnerabilities.extend(self.detect_improper_input_validation(code, filepath))
        vulnerabilities.extend(self.detect_information_exposure(code, filepath))
        vulnerabilities.extend(self.detect_improper_authentication(code, filepath))
        vulnerabilities.extend(self.detect_csrf(code, filepath))
        vulnerabilities.extend(self.detect_graphql_security(code, filepath))
        vulnerabilities.extend(self.detect_jwt_security(code, filepath))
        vulnerabilities.extend(self.detect_nosql_injection(code, filepath))
        vulnerabilities.extend(self.detect_ssti(code, filepath))
        vulnerabilities.extend(self.detect_redos(code, filepath))
        vulnerabilities.extend(self.detect_incorrect_permissions(code, filepath))
        
        return vulnerabilities
    
    def detect_with_ast(self, ast_tree, code: str, filepath: str) -> List[Vulnerability]:
        """Detect vulnerabilities using AST parsing."""
        vulnerabilities = []
        lines = code.split('\n')
        
        try:
            # Walk AST and detect vulnerabilities
            for path, node in ast_tree:
                # Command injection detection
                if hasattr(node, 'member') and hasattr(node, 'member'):
                    # Runtime.exec() patterns
                    if node.member == 'exec':
                        line_num = self._get_line_number(node.position.line if hasattr(node, 'position') and node.position else 1)
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-78',
                            severity='critical',
                            title='Command Injection via exec()',
                            description='exec() method detected. Use ProcessBuilder with arguments array instead.',
                            code=code,
                            filepath=filepath,
                            line_number=line_num
                        ))
                    
                    # SQL injection detection
                    elif node.member in ['executeQuery', 'execute', 'executeUpdate']:
                        line_num = self._get_line_number(node.position.line if hasattr(node, 'position') and node.position else 1)
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-89',
                            severity='high',
                            title='Potential SQL Injection',
                            description=f'SQL query execution via {node.member}. Use PreparedStatement with parameterized queries.',
                            code=code,
                            filepath=filepath,
                            line_number=line_num
                        ))
                
                # Path traversal detection
                elif hasattr(node, 'name'):
                    if node.name == 'File':
                        line_num = self._get_line_number(node.position.line if hasattr(node, 'position') and node.position else 1)
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-22',
                            severity='high',
                            title='Potential Path Traversal',
                            description='File constructor used. Validate file paths to prevent directory traversal.',
                            code=code,
                            filepath=filepath,
                            line_number=line_num
                        ))
                
                # Weak crypto detection
                elif hasattr(node, 'member') and node.member == 'getInstance':
                    # Check for weak algorithms
                    if hasattr(node, 'arguments') and node.arguments:
                        for arg in node.arguments:
                            if hasattr(arg, 'value'):
                                algo = str(arg.value).replace('"', '').replace("'", "")
                                if algo.upper() in ['MD5', 'SHA-1', 'SHA1', 'DES', 'RC4']:
                                    line_num = self._get_line_number(node.position.line if hasattr(node, 'position') and node.position else 1)
                                    vulnerabilities.append(self._create_vulnerability(
                                        cwe='CWE-327',
                                        severity='medium',
                                        title='Weak Cryptographic Algorithm',
                                        description=f'Use of weak algorithm {algo}. Use SHA-256 or AES-256 instead.',
                                        code=code,
                                        filepath=filepath,
                                        line_number=line_num
                                    ))
        except Exception as e:
            # If AST parsing fails, fall through to regex
            pass
        
        return vulnerabilities
    
    def _get_line_number(self, line_num):
        """Get line number, defaulting to 1 if invalid."""
        try:
            return int(line_num) if line_num and line_num > 0 else 1
        except:
            return 1
    
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection in Java."""
        patterns = [
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Runtime.exec'),
            (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder with concatenation'),
            (r'\.exec\s*\([^)]*\+', 'exec with string concatenation'),
            (r'new\s+ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder constructor'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, method in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='OS Command Injection',
                        description=f'Potential command injection using {method}. Use parameterized commands.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection in Java."""
        patterns = [
            r'Statement\.executeQuery\s*\([^)]*\+',
            r'Statement\.execute\s*\([^)]*\+',
            r'createStatement\(\)\.execute\w*\s*\([^)]*\+',
            r'\.executeQuery\s*\(\s*["\'].*\+',
            r'PreparedStatement.*["\'].*\+.*["\']',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='SQL Injection',
                        description='Potential SQL injection. Use PreparedStatement with parameterized queries.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS in Java."""
        patterns = [
            r'\.println\s*\([^)]*request\.getParameter',
            r'out\.write\s*\([^)]*request\.getParameter',
            r'response\.getWriter\(\)\.write\s*\([^)]*request',
            r'\.append\s*\([^)]*request\.getParameter',
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
                        description='Potential XSS vulnerability. Sanitize user input before output.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal in Java."""
        patterns = [
            r'new\s+File\s*\([^)]*request\.getParameter',
            r'new\s+FileInputStream\s*\([^)]*request',
            r'new\s+FileReader\s*\([^)]*request',
            r'Files\.read\w*\s*\([^)]*request',
            r'Paths\.get\s*\([^)]*request',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-22',
                        severity='high',
                        title='Path Traversal',
                        description='Potential path traversal. Validate and sanitize file paths.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography in Java."""
        patterns = [
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', 'MD5'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', 'SHA-1'),
            (r'Cipher\.getInstance\s*\(\s*["\']DES[/"]', 'DES'),
            (r'Cipher\.getInstance\s*\(\s*["\']RC4', 'RC4'),
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
                        description=f'Use of weak algorithm {algo}. Use AES-256 or SHA-256.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials in Java."""
        patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'apiKey\s*=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'private_key\s*=\s*["\']', 'private key'),
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if '//' in line or '/*' in line:
                continue
            
            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Hardcoded Credentials',
                        description=f'Hardcoded {cred_type}. Use configuration management or key vaults.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization in Java."""
        patterns = [
            r'ObjectInputStream\.readObject\s*\(\)',
            r'XMLDecoder\.readObject\s*\(\)',
            r'\.deserialize\s*\(',
            r'XStream\s*\(\)',
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
                        description='Unsafe deserialization. Validate and filter deserialized objects.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xxe(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XXE in Java."""
        patterns = [
            r'DocumentBuilderFactory\.newInstance\(\)',
            r'SAXParserFactory\.newInstance\(\)',
            r'XMLInputFactory\.newInstance\(\)',
            r'TransformerFactory\.newInstance\(\)',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check for XXE protection
                    code_window = '\n'.join(lines[max(0,i-3):min(len(lines),i+3)])
                    if 'setFeature' not in code_window or 'FEATURE_SECURE_PROCESSING' not in code_window:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-611',
                            severity='high',
                            title='XML External Entity (XXE) Injection',
                            description='XML parser without XXE protection. Disable external entities.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_ldap_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect LDAP injection in Java."""
        patterns = [
            r'\.search\s*\([^)]*\+[^)]*request',
            r'LdapContext\.search\s*\([^)]*\+',
            r'InitialDirContext\.search\s*\([^)]*\+',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-90',
                        severity='high',
                        title='LDAP Injection',
                        description='Potential LDAP injection. Sanitize user input in LDAP queries.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_xpath_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XPath injection in Java."""
        patterns = [
            r'\.compile\s*\([^)]*\+[^)]*request',
            r'XPath\.evaluate\s*\([^)]*\+',
            r'XPathExpression\.evaluate\s*\([^)]*\+',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-643',
                        severity='high',
                        title='XPath Injection',
                        description='Potential XPath injection. Use parameterized XPath queries.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_weak_random(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak random number generation in Java."""
        patterns = [
            r'new\s+Random\s*\(',
            r'Math\.random\s*\(',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if it's security-related
                    code_window = '\n'.join(lines[max(0,i-5):min(len(lines),i+5)])
                    security_keywords = ['password', 'token', 'key', 'secret', 'crypto', 'salt']
                    if any(keyword in code_window.lower() for keyword in security_keywords):
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-330',
                            severity='medium',
                            title='Weak Random Number Generation',
                            description='Use SecureRandom for cryptographic purposes instead of Random.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SSRF vulnerabilities in Java."""
        patterns = [
            r'URL\([^)]*request\.getParameter',
            r'new URL\s*\([^)]*\+',
            r'HttpURLConnection\.\w*\([^)]*\+',
            r'\.openConnection\s*\([^)]*\+',
        ]
        
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-918',
                        severity='high',
                        title='Server-Side Request Forgery (SSRF)',
                        description='Potential SSRF vulnerability. Validate and whitelist URLs before making requests.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_missing_encryption_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-311: Missing Encryption of Sensitive Data in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            patterns = [
                (r'\.setPassword\s*\(', 'setPassword'),
                (r'\.setApiKey\s*\(', 'setApiKey'),
                (r'private\s+.*password\s*=\s*"', 'field password'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                    has_encryption = any(enc in context.lower() for enc in ['encrypt', 'hash', 'bcrypt', 'sha256'])
                    
                    if not has_encryption:
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-311',
                            severity='high',
                            title='Missing Encryption',
                            description=f'Sensitive data in {desc} without encryption. Encrypt at rest.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
                        break
        
        return vulnerabilities
    
    def detect_weak_certificate_validation_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-295: Improper Certificate Validation in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'TrustManager.*acceptAll|checkClientTrusted.*ignore|checkServerTrusted.*ignore', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-295',
                    severity='high',
                    title='Improper Certificate Validation',
                    description='Custom TrustManager that accepts all certificates. Always validate certificates.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_hardcoded_crypto_key_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-321: Hard-coded Cryptographic Key in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'private\s+.*key\s*=\s*["\']', line, re.IGNORECASE) or \
               re.search(r'\.init\s*\(.*getBytes\s*\(["\']', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-321',
                    severity='critical',
                    title='Hard-coded Cryptographic Key',
                    description='Hard-coded encryption key detected. Use environment variables or key management.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_insecure_http_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-319: Cleartext Transmission in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\"http://', line, re.IGNORECASE):
                vulnerabilities.append(self._create_vulnerability(
                    cwe='CWE-319',
                    severity='high',
                    title='Cleartext Transmission',
                    description='HTTP used instead of HTTPS. Use encrypted transport.',
                    code=code,
                    filepath=filepath,
                    line_number=i
                ))
        
        return vulnerabilities
    
    def detect_error_message_disclosure_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-209: Information Disclosure in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'throw new \w+Exception\s*\(.*\+|\.printStackTrace\s*\(', line):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+1)])
                if 'test' not in filepath.lower() and \
                   not any(safe in context.lower() for safe in ['logger', 'log']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-209',
                        severity='low',
                        title='Error Message Information Disclosure',
                        description='Verbose exception messages may leak information. Use generic messages.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_improper_session_management_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-384: Session Fixation in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'request\.getSession\s*\(', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if 'login' in context.lower() or 'authenticate' in context.lower():
                    if 'true' not in context and 'invalidate' not in context.lower():
                        vulnerabilities.append(self._create_vulnerability(
                            cwe='CWE-384',
                            severity='medium',
                            title='Session Fixation',
                            description='Session ID not invalidated on login. Regenerate session ID.',
                            code=code,
                            filepath=filepath,
                            line_number=i
                        ))
        
        return vulnerabilities
    
    def detect_http_header_injection_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-113: HTTP Header Injection in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.setHeader\s*\(.*\+|response\.addHeader\s*\(.*\+', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+2)])
                if not ('\\r\\n' in context or '\\n' in context or 'replace' in context.lower()):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-113',
                        severity='high',
                        title='HTTP Header Injection',
                        description='User input in HTTP headers. Sanitize CRLF sequences.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_race_condition_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-362: Race Condition in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'FileWriter|BufferedWriter.*write', line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if re.search(r'volatile|synchronized|lock', context, re.IGNORECASE):
                    continue  # Has locking
                if any(shared in context.lower() for shared in ['static', 'shared', 'global']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-362',
                        severity='medium',
                        title='Potential Race Condition',
                        description='File write on shared resource without synchronization. Add locks.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities
    
    def detect_integer_overflow_java(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect CWE-190: Integer Overflow in Java."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\+\s*(request\.getParameter|request\.getAttribute)', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+2)])
                if not any(check in context.lower() for check in ['long', 'biginteger', 'check', 'validate']):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-190',
                        severity='low',
                        title='Potential Integer Overflow',
                        description='Arithmetic on user input without bounds checking. Use long or BigInteger.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
        
        return vulnerabilities

