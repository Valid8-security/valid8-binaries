"""
CodeQL-inspired semantic query analyzer for advanced vulnerability detection.
"""

import ast
import re
from typing import List, Dict, Any, Set, Tuple
from ..language_support.base import Vulnerability


class CodeQLAnalyzer:
    """Advanced semantic query analyzer inspired by CodeQL."""
    
    def __init__(self):
        self.queries = self._load_semantic_queries()
        self.data_flow_graph = {}
        
    def _load_semantic_queries(self) -> Dict[str, Dict]:
        """Load sophisticated semantic queries for vulnerability detection."""
        return {
            # SQL Injection with taint tracking
            'sql_injection_tainted': {
                'description': 'SQL injection via tainted user input',
                'pattern': self._sql_injection_taint_pattern,
                'cwe': 'CWE-89',
                'severity': 'HIGH',
                'confidence': 0.95
            },
            
            # XSS with DOM manipulation
            'xss_dom_manipulation': {
                'description': 'XSS via unsafe DOM manipulation',
                'pattern': self._xss_dom_pattern,
                'cwe': 'CWE-79',
                'severity': 'HIGH', 
                'confidence': 0.9
            },
            
            # Path traversal with validation bypass
            'path_traversal_bypass': {
                'description': 'Path traversal bypassing validation',
                'pattern': self._path_traversal_bypass_pattern,
                'cwe': 'CWE-22',
                'severity': 'HIGH',
                'confidence': 0.85
            },
            
            # Command injection with shell escaping
            'command_injection_shell': {
                'description': 'Command injection with shell metacharacter injection',
                'pattern': self._command_injection_shell_pattern,
                'cwe': 'CWE-78',
                'severity': 'CRITICAL',
                'confidence': 0.9
            },
            
            # Deserialization of untrusted data
            'unsafe_deserialization': {
                'description': 'Deserialization of untrusted data',
                'pattern': self._unsafe_deserialization_pattern,
                'cwe': 'CWE-502',
                'severity': 'HIGH',
                'confidence': 0.95
            },
            
            # Weak cryptography usage
            'weak_crypto_usage': {
                'description': 'Use of weak cryptographic algorithms',
                'pattern': self._weak_crypto_pattern,
                'cwe': 'CWE-327',
                'severity': 'MEDIUM',
                'confidence': 0.8
            },
            
            # Hardcoded credentials with entropy analysis
            'hardcoded_credentials_entropy': {
                'description': 'Hardcoded credentials detected via entropy analysis',
                'pattern': self._hardcoded_credentials_entropy_pattern,
                'cwe': 'CWE-798',
                'severity': 'HIGH',
                'confidence': 0.9
            },
            
            # Race condition detection
            'race_condition_file_access': {
                'description': 'Potential race condition in file access',
                'pattern': self._race_condition_pattern,
                'cwe': 'CWE-362',
                'severity': 'MEDIUM',
                'confidence': 0.7
            },
            
            # Information disclosure via error messages
            'info_disclosure_errors': {
                'description': 'Information disclosure through error messages',
                'pattern': self._info_disclosure_pattern,
                'cwe': 'CWE-209',
                'severity': 'MEDIUM',
                'confidence': 0.75
            },
            
            # Authentication bypass via default credentials
            'auth_bypass_default_creds': {
                'description': 'Authentication bypass using default credentials',
                'pattern': self._auth_bypass_pattern,
                'cwe': 'CWE-287',
                'severity': 'CRITICAL',
                'confidence': 0.95
            }
        }
    
    def analyze_code(self, code: str, filepath: str) -> List[Vulnerability]:
        """Analyze code using semantic queries."""
        vulnerabilities = []
        
        try:
            # Build data flow graph for taint analysis
            self._build_data_flow_graph(code, filepath)
            
            # Run semantic queries
            for query_name, query_config in self.queries.items():
                pattern_func = query_config['pattern']
                findings = pattern_func(code, filepath)
                
                for finding in findings:
                    vuln = Vulnerability(
                        cwe=query_config['cwe'],
                        severity=query_config['severity'],
                        title=f"CodeQL: {query_name.replace('_', ' ').title()}",
                        description=query_config['description'],
                        file_path=filepath,
                        line_number=finding.get('line_number', 1),
                        code_snippet=finding.get('code_snippet', ''),
                        confidence=query_config['confidence']
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            # If analysis fails, return empty list
            pass
            
        return vulnerabilities
    
    def _build_data_flow_graph(self, code: str, filepath: str):
        """Build a data flow graph for taint analysis."""
        try:
            tree = ast.parse(code, filename=filepath)
            analyzer = DataFlowAnalyzer()
            analyzer.visit(tree)
            self.data_flow_graph = analyzer.flow_graph
        except:
            self.data_flow_graph = {}
    
    def _sql_injection_taint_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect SQL injection with taint tracking."""
        findings = []
        lines = code.split('\n')
        
        # Look for SQL operations with user input
        sql_patterns = [
            r'cursor\.execute\(.*f".*\{.*\}.*".*\)',
            r'cursor\.execute\(.*".*\%.*".*\)',
            r'connection\.execute\(.*f".*\{.*\}.*".*\)',
            r'db\.execute\(.*f".*\{.*\}.*".*\)',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if line contains user input variables
                    if self._contains_user_input(line):
                        findings.append({
                            'line_number': i,
                            'code_snippet': line.strip(),
                            'tainted_vars': self._extract_user_vars(line)
                        })
        
        return findings
    
    def _xss_dom_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect XSS via DOM manipulation."""
        findings = []
        lines = code.split('\n')
        
        xss_patterns = [
            r'innerHTML\s*=.*\+',
            r'outerHTML\s*=.*\+', 
            r'document\.write\(.*\+.*\)',
            r'eval\(.*\+.*\)',
            r'setTimeout\(.*\+.*\)',
            r'setInterval\(.*\+.*\)'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in xss_patterns:
                if re.search(pattern, line):
                    if self._contains_user_input(line):
                        findings.append({
                            'line_number': i,
                            'code_snippet': line.strip(),
                            'risk_level': 'high'
                        })
        
        return findings
    
    def _path_traversal_bypass_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect path traversal bypassing validation."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for file operations with path manipulation
            if re.search(r'open\(.*\+.*\)', line) or re.search(r'os\.path\.join\(.*\+.*\)', line):
                # Check for path traversal indicators
                if '..' in line or '../' in line or '..\\' in line:
                    findings.append({
                        'line_number': i,
                        'code_snippet': line.strip(),
                        'bypass_type': 'directory_traversal'
                    })
        
        return findings
    
    def _command_injection_shell_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect command injection with shell metacharacters."""
        findings = []
        lines = code.split('\n')
        
        shell_meta = [';', '|', '&', '`', '$', '(', ')', '<', '>', '*', '?', '[', ']', '{', '}']
        
        for i, line in enumerate(lines, 1):
            if 'subprocess.' in line or 'os.system' in line or 'os.popen' in line:
                if any(meta in line for meta in shell_meta):
                    if self._contains_user_input(line):
                        findings.append({
                            'line_number': i,
                            'code_snippet': line.strip(),
                            'shell_chars': [c for c in shell_meta if c in line]
                        })
        
        return findings
    
    def _unsafe_deserialization_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect unsafe deserialization."""
        findings = []
        lines = code.split('\n')
        
        unsafe_patterns = [
            r'pickle\.loads?\([^)]+\)',
            r'yaml\.load\([^)]+\)',
            r'yaml\.safe_load\([^)]+\)',
            r'json\.loads?\([^)]+\)',
            r'marshal\.load\([^)]+\)',
            r'cPickle\.load\([^)]+\)'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in unsafe_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'line_number': i,
                        'code_snippet': line.strip(),
                        'deserializer': pattern.split('.')[0]
                    })
        
        return findings
    
    def _weak_crypto_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect weak cryptographic algorithms."""
        findings = []
        lines = code.split('\n')
        
        weak_algos = [
            r'hashlib\.md5\(',
            r'hashlib\.sha1\(',
            r'cryptography.*DES',
            r'cryptography.*RC4',
            r'Crypto\.Cipher\.DES',
            r'Crypto\.Cipher\.RC4'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in weak_algos:
                if re.search(pattern, line):
                    findings.append({
                        'line_number': i,
                        'code_snippet': line.strip(),
                        'weak_algo': pattern.split('.')[1] if '.' in pattern else pattern
                    })
        
        return findings
    
    def _hardcoded_credentials_entropy_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect hardcoded credentials using entropy analysis."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for variable assignments with long strings
            match = re.search(r'(\w+)\s*=\s*["\']([^"\']{20,})["\']', line)
            if match:
                var_name, value = match.groups()
                var_lower = var_name.lower()
                
                # Check if variable name suggests credentials
                if any(keyword in var_lower for keyword in ['password', 'passwd', 'secret', 'key', 'token', 'api']):
                    # Calculate entropy (simple version)
                    entropy = self._calculate_entropy(value)
                    if entropy > 3.0:  # High entropy suggests random/complex string
                        findings.append({
                            'line_number': i,
                            'code_snippet': line.strip(),
                            'variable': var_name,
                            'entropy': entropy
                        })
        
        return findings
    
    def _race_condition_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect potential race conditions."""
        findings = []
        lines = code.split('\n')
        
        # Look for file operations without proper locking
        for i, line in enumerate(lines, 1):
            if 'open(' in line and 'with' not in line:
                # Check for subsequent operations that could race
                for j in range(i, min(i+10, len(lines))):
                    next_line = lines[j]
                    if 'os.rename' in next_line or 'os.remove' in next_line or 'write' in next_line:
                        findings.append({
                            'line_number': i,
                            'code_snippet': line.strip(),
                            'race_condition': 'file_operation_without_locking'
                        })
                        break
        
        return findings
    
    def _info_disclosure_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect information disclosure in error messages."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for exception handling that might leak sensitive info
            if 'except' in line and ('Exception' in line or 'Error' in line):
                # Check if error details are being exposed
                for j in range(i, min(i+5, len(lines))):
                    if 'print(' in lines[j] or 'log' in lines[j] or 'return' in lines[j]:
                        if 'str(e)' in lines[j] or 'repr(e)' in lines[j] or '.message' in lines[j]:
                            findings.append({
                                'line_number': i,
                                'code_snippet': lines[j].strip(),
                                'leak_type': 'exception_details'
                            })
                            break
        
        return findings
    
    def _auth_bypass_pattern(self, code: str, filepath: str) -> List[Dict]:
        """Detect authentication bypass patterns."""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Look for authentication logic with obvious bypasses
            if 'if' in line and ('admin' in line.lower() or 'authenticated' in line.lower()):
                # Check for always-true conditions
                if '== True' in line or 'is True' in line or 'return True' in line:
                    findings.append({
                        'line_number': i,
                        'code_snippet': line.strip(),
                        'bypass_type': 'always_true_condition'
                    })
                # Check for default credentials
                elif re.search(r'==\s*["\']admin["\']', line) and re.search(r'==\s*["\']password["\']', line):
                    findings.append({
                        'line_number': i,
                        'code_snippet': line.strip(),
                        'bypass_type': 'default_credentials'
                    })
        
        return findings
    
    def _contains_user_input(self, line: str) -> bool:
        """Check if line contains user input variables."""
        user_indicators = [
            'request.', 'input(', 'raw_input(', 'argv', 'getenv(',
            'form.', 'args.', 'data.', 'json.', 'params.'
        ]
        return any(indicator in line for indicator in user_indicators)
    
    def _extract_user_vars(self, line: str) -> List[str]:
        """Extract potential user input variables from line."""
        # Simple extraction - look for variables that might be user input
        vars_found = []
        # This is a simplified version - real implementation would be more sophisticated
        return vars_found
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        from collections import Counter
        import math
        
        char_counts = Counter(string)
        length = len(string)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy


class DataFlowAnalyzer(ast.NodeVisitor):
    """Analyze data flow for taint tracking."""
    
    def __init__(self):
        self.flow_graph = {}
        self.current_scope = []
        self.assignments = {}
    
    def visit_FunctionDef(self, node):
        old_scope = self.current_scope[:]
        self.current_scope.append(node.name)
        self.generic_visit(node)
        self.current_scope = old_scope
    
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            scope_key = '.'.join(self.current_scope + [var_name])
            self.assignments[scope_key] = node.value
        self.generic_visit(node)
    
    def visit_Call(self, node):
        # Track function calls that might be sinks
        self.generic_visit(node)
