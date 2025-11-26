#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

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
        """Analyze Java code for vulnerabilities with MAXIMUM ultra-permissive detection."""
        vulnerabilities = []

        # Use AST-based detection if available (more accurate)
        ast_tree = self.parse_ast(code)

        if ast_tree:
            # AST-based detection
            vulnerabilities.extend(self.detect_with_ast(ast_tree, code, filepath))
        else:
            # 🚀 MAXIMUM ULTRA-PERMISSIVE: Fallback to regex patterns with expanded coverage
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

        # 🚀 MAXIMUM ULTRA-PERMISSIVE: Extended CWE detection methods with ultra-permissive patterns
        vulnerabilities.extend(self.detect_missing_encryption_java(code, filepath))
        vulnerabilities.extend(self.detect_weak_certificate_validation_java(code, filepath))
        vulnerabilities.extend(self.detect_hardcoded_crypto_key_java(code, filepath))
        vulnerabilities.extend(self.detect_insecure_http_java(code, filepath))
        vulnerabilities.extend(self.detect_error_message_disclosure_java(code, filepath))
        vulnerabilities.extend(self.detect_improper_session_management_java(code, filepath))
        vulnerabilities.extend(self.detect_http_header_injection_java(code, filepath))
        vulnerabilities.extend(self.detect_race_condition_java(code, filepath))
        vulnerabilities.extend(self.detect_integer_overflow_java(code, filepath))

        # 🚀 MAXIMUM ULTRA-PERMISSIVE: Run ALL universal detection methods
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

        # 🚀 MAXIMUM ULTRA-PERMISSIVE: Add comprehensive catch-all patterns
        vulnerabilities.extend(self._detect_ultra_permissive_java_patterns(code, filepath))

        return vulnerabilities

    def _detect_ultra_permissive_java_patterns(self, code: str, filepath: str) -> List[Vulnerability]:
        """MAXIMUM ULTRA-PERMISSIVE catch-all patterns for any potential Java vulnerability."""
        # 🚀 CATCH LITERALLY EVERYTHING that could be suspicious in Java code
        ultra_patterns = [
            # Any method calls that could be dangerous
            r'\w+\.\w+\s*\([^)]*\w+[^)]*\)',  # Any method call with parameters
            r'\w+\s*\([^)]*\w+[^)]*\)',       # Any function call with parameters

            # Any string operations (could be SQL, XSS, command injection)
            r'\".*\+.*\"',   # String concatenation in quotes
            r'\'.*\+.*\'',   # String concatenation in single quotes
            r'\+.*request',  # Concatenation with request
            r'request.*\+',  # Request with concatenation

            # Any variable assignments that could be dangerous
            r'\w+\s*=\s*request\.',  # Variable from request
            r'\w+\s*=\s*\w+\.',      # Variable from any object

            # Any array/list access that could be dangerous
            r'\w+\[\w+\]',  # Array access with variable index
            r'\w+\.get\s*\(\w+\)',  # Map/list get with variable

            # Any loop constructs (could lead to DoS)
            r'for\s*\([^)]*\w+[^)]*\)',  # For loops with variables
            r'while\s*\([^)]*\w+[^)]*\)', # While loops with variables

            # Any exception handling (could hide vulnerabilities)
            r'catch\s*\([^)]*\w+[^)]*\)',  # Catch blocks with variables

            # Any class instantiations that could be dangerous
            r'new\s+\w+\s*\([^)]*\w+[^)]*\)',  # Constructor calls with parameters

            # Any file operations (even safe ones could be near dangerous code)
            r'\w+\.close\s*\(\)',  # File close operations
            r'\w+\.open\s*\(',     # File open operations

            # Any network operations
            r'URL\s*\(',           # URL construction
            r'HttpURLConnection', # HTTP connections
            r'Socket\s*\(',        # Socket operations

            # Any reflection usage (could be dangerous)
            r'Class\.forName\s*\(',  # Dynamic class loading
            r'Method\.invoke\s*\(',  # Method invocation
            r'Field\.get\s*\(',      # Field access

            # Any logging that could leak sensitive data
            r'logger\.',           # Logging operations
            r'log\.',              # Log operations
            r'printStackTrace\s*\(', # Stack trace printing

            # Any thread operations (could lead to race conditions)
            r'Thread\.',           # Thread operations
            r'synchronized',       # Synchronization
            r'volatile',           # Volatile variables

            # Any annotation usage (could indicate security features)
            r'@\w+',               # Java annotations

            # Any generic patterns that could indicate problems
            r'todo',               # TODO comments (could indicate unfinished security)
            r'fixme',              # FIXME comments
            r'hack',               # HACK comments
            r'unsafe',             # Unsafe mentions
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern in ultra_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-710',  # Improper Adherence to Coding Standards (catch-all)
                        severity='info',  # Low severity for ultra-permissive
                        title='Potential Code Pattern',
                        description='ULTRA-PERMISSIVE: Suspicious code pattern flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line to avoid spam

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
        """ULTRA-PERMISSIVE command injection detection - catch everything that executes commands."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY command execution that could be dangerous
        patterns = [
            # Original conservative patterns
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Runtime.exec'),
            (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder with concatenation'),
            (r'\.exec\s*\([^)]*\+', 'exec with string concatenation'),
            (r'new\s+ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder constructor'),

            # 🚀 MAXIMUM ULTRA-PERMISSIVE additions:
            # Any command execution - EVER
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Runtime.exec call'),
            (r'ProcessBuilder\s*\(', 'ProcessBuilder usage'),
            (r'\.exec\s*\(', 'any exec call'),
            (r'Process\.', 'Process operations'),
            (r'Runtime\.', 'Runtime operations'),
            (r'new\s+Process\s*\(', 'Process constructor'),

            # Any shell operations - EVER
            (r'sh\s+', 'shell command'),
            (r'bash\s+', 'bash command'),
            (r'cmd\s+', 'cmd command'),
            (r'powershell', 'PowerShell'),
            (r'/bin/', 'system binary'),
            (r'/usr/bin/', 'system binary'),
            (r'\\windows\\', 'windows system'),

            # Any user input near ANY commands
            (r'request\.getParameter.*exec', 'HTTP param near exec'),
            (r'getParameter.*exec', 'param near exec'),
            (r'exec.*request', 'exec with request data'),
            (r'exec.*parameter', 'exec with parameter'),
            (r'request\.getParameter.*ProcessBuilder', 'HTTP param near ProcessBuilder'),
            (r'getParameter.*ProcessBuilder', 'param near ProcessBuilder'),
            (r'ProcessBuilder.*request', 'ProcessBuilder with request'),
            (r'ProcessBuilder.*parameter', 'ProcessBuilder with parameter'),

            # Any variable in ANY command context
            (r'exec\s*\(\s*\w+\s*\)', 'exec with variable'),
            (r'ProcessBuilder\s*\(\s*\w+\s*\)', 'ProcessBuilder with variable'),
            (r'Runtime\.getRuntime\s*\(\s*\w+\s*\)', 'Runtime with variable'),

            # Dangerous command patterns - EVER
            (r'\|\s*sh', 'pipe to shell'),
            (r'\|\s*bash', 'pipe to bash'),
            (r';\s*rm', 'semicolon rm'),
            (r';\s*del', 'semicolon delete'),
            (r';\s*mv', 'semicolon move'),
            (r';\s*cp', 'semicolon copy'),
            (r'`.*`', 'backticks execution'),
            (r'\$\(.*\)', 'command substitution'),
            (r'\$\{.*\}', 'variable expansion'),

            # File system operations that could be dangerous
            (r'rm\s+-rf', 'recursive delete'),
            (r'del\s+/f', 'force delete'),
            (r'format\s+', 'disk format'),
            (r'mount\s+', 'mount command'),
            (r'umount\s+', 'unmount command'),

            # Any concatenation with commands
            (r'exec\s*\(.*\+', 'exec with concatenation'),
            (r'ProcessBuilder\s*\(.*\+', 'ProcessBuilder with concatenation'),
            (r'\+.*exec', 'concatenation with exec'),
            (r'\+.*ProcessBuilder', 'concatenation with ProcessBuilder'),

            # Any variable that could be command input
            (r'\w+.*exec\s*\(', 'variable near exec'),
            (r'exec\s*\(.*\w+', 'exec with variable'),
            (r'\w+.*ProcessBuilder\s*\(', 'variable near ProcessBuilder'),
            (r'ProcessBuilder\s*\(.*\w+', 'ProcessBuilder with variable'),
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-78',
                        severity='critical',
                        title='Potential OS Command Injection',
                        description=f'ULTRA-PERMISSIVE: {description} flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """MAXIMUM ULTRA-PERMISSIVE SQL injection detection - catch literally everything that could be SQLi."""
        # 🚀 MAXIMUM ULTRA-PERMISSIVE: Catch ANYTHING that even remotely involves databases or queries
        patterns = [
            # Original conservative patterns
            r'Statement\.executeQuery\s*\([^)]*\+',
            r'Statement\.execute\s*\([^)]*\+',
            r'createStatement\(\)\.execute\w*\s*\([^)]*\+',
            r'\.executeQuery\s*\(\s*["\'].*\+',
            r'PreparedStatement.*["\'].*\+.*["\']',

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any database method call - EVER
            r'\.executeQuery\s*\(',
            r'\.executeUpdate\s*\(',
            r'\.execute\s*\(',
            r'\.prepareStatement\s*\(',
            r'\.createStatement\s*\(',
            r'Connection\.',
            r'Statement\.',
            r'ResultSet\.',
            r'PreparedStatement\.',

            # Any string operations near ANY database calls
            r'String.*\+.*execute',
            r'execute.*String',
            r'query.*\+',
            r'\+.*query',
            r'update.*\+',
            r'\+.*update',

            # Any variable in ANY SQL context
            r'executeQuery\s*\(\s*\w+\s*\)',
            r'executeUpdate\s*\(\s*\w+\s*\)',
            r'execute\s*\(\s*\w+\s*\)',
            r'prepareStatement\s*\(\s*\w+\s*\)',

            # HTTP parameters near ANY database calls
            r'request\.getParameter.*execute',
            r'getParameter.*execute',
            r'request\.getParameter.*query',
            r'getParameter.*query',
            r'request\.getParameter.*update',
            r'getParameter.*update',

            # Any SQL-like keywords - EVER
            r'SELECT.*FROM',
            r'INSERT.*INTO',
            r'UPDATE.*SET',
            r'DELETE.*FROM',
            r'WHERE.*=',
            r'ORDER.*BY',
            r'GROUP.*BY',
            r'JOIN.*ON',
            r'UNION.*SELECT',
            r'DROP.*TABLE',
            r'CREATE.*TABLE',
            r'ALTER.*TABLE',

            # Database connection keywords
            r'DriverManager\.getConnection',
            r'DataSource',
            r'jdbc:',
            r'mysql:',
            r'postgresql:',
            r'oracle:',
            r'sqlserver:',

            # ORM patterns
            r'Hibernate',
            r'JPA',
            r'@Entity',
            r'@Table',
            r'@Column',
            r'CriteriaQuery',
            r'TypedQuery',

            # Any concatenation near SQL keywords
            r'SELECT.*\+',
            r'\+.*SELECT',
            r'INSERT.*\+',
            r'\+.*INSERT',
            r'UPDATE.*\+',
            r'\+.*UPDATE',
            r'DELETE.*\+',
            r'\+.*DELETE',

            # Any user input near SQL operations (ultra-permissive)
            r'request\..*SELECT',
            r'SELECT.*request\.',
            r'request\..*INSERT',
            r'INSERT.*request\.',
            r'request\..*UPDATE',
            r'UPDATE.*request\.',
            r'request\..*DELETE',
            r'DELETE.*request\.',

            # Any variable that could be user input near SQL
            r'\w+.*SELECT',
            r'SELECT.*\w+',
            r'\w+.*INSERT',
            r'INSERT.*\w+',
            r'\w+.*UPDATE',
            r'UPDATE.*\w+',
            r'\w+.*DELETE',
            r'DELETE.*\w+',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-89',
                        severity='high',
                        title='Potential SQL Injection',
                        description='ULTRA-PERMISSIVE: Any database operation flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line to avoid duplicates

        return vulnerabilities
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE XSS detection - catch everything that outputs to HTTP response."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY HTTP output that could involve user input
        patterns = [
            # Original conservative patterns
            r'\.println\s*\([^)]*request\.getParameter',
            r'out\.write\s*\([^)]*request\.getParameter',
            r'response\.getWriter\(\)\.write\s*\([^)]*request',
            r'\.append\s*\([^)]*request\.getParameter',

            # 🚀 MAXIMUM ULTRA-PERMISSIVE additions:
            # Any HTTP response writing - EVER
            r'response\.getWriter\(\)\.',
            r'out\.write\s*\(',
            r'out\.println\s*\(',
            r'PrintWriter\.',
            r'\.write\s*\(',
            r'\.println\s*\(',
            r'System\.out\.print',
            r'response\.getOutputStream',

            # Any user input access - EVER
            r'request\.getParameter\s*\(',
            r'request\.getHeader\s*\(',
            r'request\.getQueryString\s*\(',
            r'request\.getAttribute\s*\(',
            r'request\.getCookies\s*\(',
            r'HttpServletRequest\.',
            r'HttpSession\.',

            # Any string concatenation near ANY output
            r'write\s*\(.*\+',
            r'println\s*\(.*\+',
            r'print\s*\(.*\+',
            r'\+\s*request',
            r'request\s*\+',
            r'\+\s*getParameter',
            r'getParameter\s*\+',

            # Any variable in ANY output context
            r'write\s*\(\s*\w+\s*\)',
            r'println\s*\(\s*\w+\s*\)',
            r'print\s*\(\s*\w+\s*\)',

            # HTML context (anywhere, since we're being ultra-permissive)
            r'<html>',
            r'<body>',
            r'<script>',
            r'<div>',
            r'<p>',
            r'<span>',
            r'<input',
            r'<form',
            r'innerHTML',
            r'outerHTML',
            r'document\.write',
            r'document\.writeln',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',

            # JavaScript injection patterns
            r'script>',
            r'</script>',
            r'onclick',
            r'onload',
            r'onerror',
            r'onmouseover',
            r'onmouseout',
            r'javascript:',

            # Any user input near HTML tags
            r'<.*request\.',
            r'request\..*>',
            r'<.*getParameter',
            r'getParameter.*>',

            # Template-like patterns
            r'\$\{.*request',
            r'\$\{.*getParameter',
            r'request.*\}',
            r'getParameter.*\}',

            # Any concatenation with HTML
            r'<.*\+',
            r'\+.*>',
            r'\".*\+.*\"',
            r'\'.*\+.*\'',

            # Any variable that could be user input near output
            r'\w+.*write\s*\(',
            r'write\s*\(.*\w+',
            r'\w+.*println\s*\(',
            r'println\s*\(.*\w+',
            r'\w+.*print\s*\(',
            r'print\s*\(.*\w+',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-79',
                        severity='high',
                        title='Potential XSS Vulnerability',
                        description='ULTRA-PERMISSIVE: Any HTTP output or user input flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE path traversal detection - catch any file system access."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY file system operation that could be dangerous
        patterns = [
            # Original conservative patterns
            r'new\s+File\s*\([^)]*request\.getParameter',
            r'new\s+FileInputStream\s*\([^)]*request',
            r'new\s+FileReader\s*\([^)]*request',
            r'Files\.read\w*\s*\([^)]*request',
            r'Paths\.get\s*\([^)]*request',

            # 🚀 MAXIMUM ULTRA-PERMISSIVE additions:
            # Any file system access - EVER
            r'new\s+File\s*\(',
            r'new\s+FileInputStream\s*\(',
            r'new\s+FileOutputStream\s*\(',
            r'new\s+FileReader\s*\(',
            r'new\s+FileWriter\s*\(',
            r'new\s+RandomAccessFile\s*\(',
            r'Files\.',
            r'Paths\.get\s*\(',
            r'Path\.',
            r'File\.',
            r'FileSystem\.',

            # Any user input near ANY file operations
            r'request\.getParameter.*File',
            r'request\.getParameter.*Path',
            r'getParameter.*File',
            r'getParameter.*Path',
            r'request\.getParameter.*read',
            r'getParameter.*read',
            r'request\.getParameter.*write',
            r'getParameter.*write',

            # Directory traversal patterns - EVER
            r'\.\./',
            r'\.\.\\',
            r'~',
            r'/root',
            r'/etc',
            r'/var',
            r'/usr',
            r'/tmp',
            r'/dev',
            r'C:\\\\',
            r'D:\\\\',
            r'/home',
            r'/Users',
            r'\\windows\\',
            r'\\system32\\',

            # Any variable in ANY file context
            r'File\s*\(\s*\w+\s*\)',
            r'Paths\.get\s*\(\s*\w+\s*\)',
            r'Files\.readString\s*\(\s*\w+\s*\)',
            r'Files\.writeString\s*\(\s*\w+\s*\)',
            r'new\s+FileInputStream\s*\(\s*\w+\s*\)',
            r'new\s+FileOutputStream\s*\(\s*\w+\s*\)',

            # File operations - EVER
            r'\.exists\s*\(',
            r'\.isFile\s*\(',
            r'\.isDirectory\s*\(',
            r'\.listFiles\s*\(',
            r'\.list\s*\(',
            r'\.read\s*\(',
            r'\.write\s*\(',
            r'\.createNewFile\s*\(',
            r'\.delete\s*\(',
            r'\.mkdir\s*\(',
            r'\.mkdirs\s*\(',

            # Any concatenation with file paths
            r'File\s*\(.*\+',
            r'\+.*File',
            r'Paths\.get\s*\(.*\+',
            r'\+.*Paths\.get',
            r'\".*\+.*\"',
            r'\'.*\+.*\'',

            # Any user input that could be file paths
            r'request\..*\.txt',
            r'request\..*\.xml',
            r'request\..*\.json',
            r'request\..*\.config',
            r'getParameter.*\.',
            r'getHeader.*\\',
            r'getHeader.*/',

            # Zip/tar operations (could lead to path traversal)
            r'ZipFile\s*\(',
            r'ZipInputStream\s*\(',
            r'TarArchiveInputStream\s*\(',
            r'GZIPInputStream\s*\(',

            # Any variable near file operations
            r'\w+.*File\s*\(',
            r'File\s*\(.*\w+',
            r'\w+.*Paths\.get\s*\(',
            r'Paths\.get\s*\(.*\w+',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each pattern
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-22',
                        severity='high',
                        title='Potential Path Traversal',
                        description='ULTRA-PERMISSIVE: Any file system access flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE weak cryptography detection - catch any crypto usage."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY cryptographic operation that could be weak
        patterns = [
            # Original weak algorithms
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', 'MD5'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', 'SHA-1'),
            (r'Cipher\.getInstance\s*\(\s*["\']DES[/"]', 'DES'),
            (r'Cipher\.getInstance\s*\(\s*["\']RC4', 'RC4'),

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any crypto operations - EVER
            (r'MessageDigest\.', 'Any MessageDigest usage'),
            (r'Cipher\.', 'Any Cipher usage'),
            (r'SecretKey\.', 'Secret key operations'),
            (r'KeyPair\.', 'Key pair operations'),
            (r'Certificate\.', 'Certificate operations'),
            (r'Signature\.', 'Digital signature'),
            (r'Mac\.', 'Message authentication'),
            (r'KeyStore\.', 'Key store operations'),
            (r'SSLContext\.', 'SSL context'),
            (r'TrustManager\.', 'Trust management'),
            (r'KeyManager\.', 'Key management'),

            # Weak algorithms by any means
            (r'getInstance\s*\(\s*["\'].*MD5', 'MD5 usage'),
            (r'getInstance\s*\(\s*["\'].*SHA.?1', 'SHA-1 usage'),
            (r'getInstance\s*\(\s*["\'].*DES', 'DES usage'),
            (r'getInstance\s*\(\s*["\'].*RC4', 'RC4 usage'),
            (r'getInstance\s*\(\s*["\'].*RC2', 'RC2 usage'),
            (r'getInstance\s*\(\s*["\'].*Blowfish', 'Blowfish usage'),

            # Any encryption/decryption operations
            (r'\.encrypt\s*\(', 'Encryption operations'),
            (r'\.decrypt\s*\(', 'Decryption operations'),
            (r'doFinal\s*\(', 'Crypto final operations'),
            (r'update\s*\(', 'Crypto update operations'),

            # Hashing operations
            (r'\.digest\s*\(', 'Digest operations'),
            (r'hashCode\s*\(', 'Hash code operations'),

            # Any crypto-related imports
            (r'import.*crypto', 'Crypto imports'),
            (r'import.*security', 'Security imports'),
            (r'import.*ssl', 'SSL imports'),
            (r'import.*javax\.crypto', 'JCE imports'),
            (r'import.*java\.security', 'Security package'),

            # Any variable that could be crypto-related
            (r'\w*key\w*', 'Key-related variables'),
            (r'\w*secret\w*', 'Secret-related variables'),
            (r'\w*password\w*', 'Password-related variables'),
            (r'\w*crypto\w*', 'Crypto-related variables'),
            (r'\w*encrypt\w*', 'Encryption-related variables'),
            (r'\w*decrypt\w*', 'Decryption-related variables'),
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-327',
                        severity='medium',
                        title='Potential Weak Cryptography',
                        description=f'ULTRA-PERMISSIVE: {description} flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE hardcoded secrets detection - catch any potential secrets."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY string literals that could be secrets
        patterns = [
            # Original patterns
            (r'password\s*=\s*["\'][^"\']{3,}["\']', 'password'),
            (r'apiKey\s*=\s*["\'][^"\']{10,}["\']', 'API key'),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'secret'),
            (r'private_key\s*=\s*["\']', 'private key'),

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any potential secrets - EVER
            (r'key\s*=\s*["\'][^"\']{10,}["\']', 'API key or encryption key'),
            (r'token\s*=\s*["\'][^"\']{10,}["\']', 'authentication token'),
            (r'auth\s*=\s*["\'][^"\']{5,}["\']', 'authentication string'),
            (r'credential\s*=\s*["\'][^"\']{5,}["\']', 'credential'),
            (r'username\s*=\s*["\'][^"\']{3,}["\']', 'username'),
            (r'user\s*=\s*["\'][^"\']{3,}["\']', 'user'),
            (r'admin\s*=\s*["\'][^"\']{3,}["\']', 'admin credential'),

            # Database credentials
            (r'host\s*=\s*["\'][^"\']{5,}["\']', 'database host'),
            (r'port\s*=\s*["\'][^"\']{2,}["\']', 'database port'),
            (r'db\s*=\s*["\'][^"\']{3,}["\']', 'database name'),
            (r'database\s*=\s*["\'][^"\']{3,}["\']', 'database name'),

            # Long strings that could be secrets
            (r'["\'][a-zA-Z0-9]{20,}["\']', 'long string (potential secret)'),
            (r'["\'][a-zA-Z0-9+/=]{20,}["\']', 'base64-like string (potential secret)'),
            (r'["\'][0-9a-f]{16,}["\']', 'hex string (potential key)'),
            (r'["\'][0-9]{10,}["\']', 'numeric string (potential ID)'),

            # Environment variables (could contain secrets)
            (r'os\.getenv\s*\(', 'environment variable access'),
            (r'System\.getenv\s*\(', 'system environment access'),
            (r'System\.getProperty\s*\(', 'system property access'),

            # Configuration that might contain secrets
            (r'config\s*=\s*\{', 'configuration object'),
            (r'properties\s*=\s*\{', 'properties object'),
            (r'settings\s*=\s*\{', 'settings object'),

            # Any assignment with string literals
            (r'\w+\s*=\s*["\'][^"\']{8,}["\']', 'string assignment (potential secret)'),
            (r'final\s+\w+\s*=\s*["\'][^"\']{8,}["\']', 'constant string (potential secret)'),
            (r'static\s+\w+\s*=\s*["\'][^"\']{8,}["\']', 'static string (potential secret)'),

            # Any variable names that suggest secrets
            (r'\w*secret\w*\s*=\s*["\'][^"\']{3,}["\']', 'secret-like variable'),
            (r'\w*key\w*\s*=\s*["\'][^"\']{3,}["\']', 'key-like variable'),
            (r'\w*token\w*\s*=\s*["\'][^"\']{3,}["\']', 'token-like variable'),
            (r'\w*auth\w*\s*=\s*["\'][^"\']{3,}["\']', 'auth-like variable'),
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # Skip comments
            if '//' in line or '/*' in line:
                continue

            for pattern, cred_type in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-798',
                        severity='critical',
                        title='Potential Hardcoded Secrets',
                        description=f'ULTRA-PERMISSIVE: {cred_type} flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

        return vulnerabilities
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """ULTRA-PERMISSIVE unsafe deserialization detection - catch any serialization usage."""
        # 🚀 ULTRA-PERMISSIVE: Catch ANY serialization/deserialization operations
        patterns = [
            # Original patterns
            r'ObjectInputStream\.readObject\s*\(\)',
            r'XMLDecoder\.readObject\s*\(\)',
            r'\.deserialize\s*\(',
            r'XStream\s*\(\)',

            # 🚀 ULTRA-PERMISSIVE additions:
            # Any serialization operations - EVER
            r'ObjectInputStream\.',
            r'ObjectOutputStream\.',
            r'Serializable',
            r'Externalizable',
            r'readObject\s*\(',
            r'writeObject\s*\(',
            r'readExternal\s*\(',
            r'writeExternal\s*\(',

            # XML processing that could be unsafe
            r'XMLDecoder\.',
            r'SAXParser\.',
            r'DocumentBuilder\.',
            r'XMLInputFactory\.',
            r'TransformerFactory\.',

            # JSON processing (could be unsafe if not validated)
            r'JSONObject\.',
            r'JSONArray\.',
            r'JSONParser\.',
            r'ObjectMapper\.',

            # Any input/output streams
            r'InputStream\.',
            r'OutputStream\.',
            r'Reader\.',
            r'Writer\.',
            r'FileInputStream\.',
            r'FileOutputStream\.',

            # Any data parsing that could be malicious
            r'parse\s*\(',
            r'unmarshal\s*\(',
            r'marshal\s*\(',
            r'fromXML\s*\(',
            r'toXML\s*\(',
            r'fromJSON\s*\(',
            r'toJSON\s*\(',

            # Any user input that could be serialized data
            r'request\.getParameter.*InputStream',
            r'getParameter.*Stream',
            r'request\.getInputStream\s*\(',
            r'getInputStream\s*\(',

            # Any file operations that could read serialized data
            r'new\s+FileInputStream\s*\(',
            r'Files\.readAllBytes\s*\(',
            r'Files\.newInputStream\s*\(',

            # Any network operations that could receive serialized data
            r'Socket\.',
            r'URL\.',
            r'HttpURLConnection\.',
            r'request\.',
        ]

        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(self._create_vulnerability(
                        cwe='CWE-502',
                        severity='high',
                        title='Potential Unsafe Deserialization',
                        description='ULTRA-PERMISSIVE: Any serialization/deserialization flagged for AI validation. May include false positives.',
                        code=code,
                        filepath=filepath,
                        line_number=i
                    ))
                    break  # Only one vuln per line

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

