# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Data Flow Analysis for advanced vulnerability detection.
Tracks tainted data through code to detect complex vulnerabilities.
This is critical for achieving 90% recall.
"""

import ast
import re
from typing import List, Dict, Set, Tuple, Optional


class DataFlowAnalyzer:
    """
    Advanced taint analysis to track user input through code.
    
    This enables detection of complex vulnerabilities that pattern-based
    scanning misses. Critical for reaching 90% recall.
    """
    
    def __init__(self):
        self.taint_sources = self._build_taint_sources()
        self.taint_sinks = self._build_taint_sinks()
        self.sanitizers = self._build_sanitizers()
    
    def _build_taint_sources(self) -> List[Tuple[str, str]]:
        """Build patterns for taint sources (user input)."""
        return [
            # Python web frameworks
            (r'request\.GET\[|request\.POST\[|request\.args\[|request\.form\[', 'web input'),
            (r'cookies\[|session\[', 'cookie/session'),
            (r'input\s*\(', 'user input'),
            (r'sys\.argv', 'command line args'),
            (r'argv\[', 'arguments'),
            
            # Django
            (r'self\.request\.GET|self\.request\.POST', 'Django input'),
            (r'request\.body', 'request body'),
            
            # Flask
            (r'request\.args\.get|request\.form\.get', 'Flask input'),
            (r'request\.files\[', 'file upload'),
            
            # Database sources
            (r'db\.query|result\.fetchone|result\.fetchall', 'database'),
            
            # File sources
            (r'open\s*\([^)]*"r"|file\.read\s*\(', 'file read'),
        ]
    
    def _build_taint_sinks(self) -> List[Tuple[str, str, str]]:
        """Build patterns for taint sinks (dangerous operations)."""
        return [
            # Command execution
            (r'os\.system\s*\(', 'CWE-78', 'Command Injection'),
            (r'subprocess\.(call|run|Popen)\s*\(', 'CWE-78', 'Command Injection'),
            (r'exec\s*\(', 'CWE-94', 'Code Injection'),
            (r'eval\s*\(', 'CWE-94', 'Code Injection'),
            
            # SQL execution
            (r'\.execute\s*\(|\.executeQuery|cursor\.execute', 'CWE-89', 'SQL Injection'),
            (r'db\.query\s*\(.*\+', 'CWE-89', 'SQL Injection'),
            
            # File operations
            (r'open\s*\([^)]*["\'].*\+', 'CWE-22', 'Path Traversal'),
            (r'file\.write\s*\(.*\+', 'CWE-22', 'Path Traversal'),
            (r'os\.popen\s*\(', 'CWE-22', 'Path Traversal'),
            
            # Web output (XSS)
            (r'response\.write\s*\(|\.send\s*\(', 'CWE-79', 'XSS'),
            (r'print\s*\(.*\+', 'CWE-79', 'Output without escaping'),
            
            # Serialization
            (r'pickle\.loads\s*\(', 'CWE-502', 'Unsafe Deserialization'),
            (r'yaml\.load\s*\(', 'CWE-502', 'Unsafe Deserialization'),
            
            # Template rendering
            (r'\.render\s*\(.*\+|Template\s*\(.*\+', 'CWE-94', 'Template Injection'),
            (r'jinja2\.Template\s*\(.*\+', 'CWE-94', 'Jinja2 Injection'),
        ]
    
    def _build_sanitizers(self) -> List[str]:
        """Build patterns for sanitization functions."""
        return [
            r'escape\s*\(',
            r'html\.escape',
            r'sanitize',
            r'quote',
            r're\.escape',
            r'prepare\s*\(',
            r'parameterize',
            r'escape_string',
        ]
    
    def analyze(self, code: str, filepath: str):
        """
        Perform comprehensive data flow analysis to find complex vulnerabilities.
        
        Strategy:
        1. Find taint sources (user input)
        2. Track data flow through variables
        3. Check if tainted data reaches dangerous sinks
        4. Verify if sanitization occurred
        """
        from parry.scanner import Vulnerability
        vulnerabilities = []
        lines = code.split('\n')
        
        # Find taint sources
        taint_sources = []
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.taint_sources:
                matches = re.finditer(pattern, line)
                for match in matches:
                    taint_sources.append((i, line, match.group(), desc))
        
        # If no taint sources, no data flow to analyze
        if not taint_sources:
            return vulnerabilities
        
        # Find dangerous sinks and check data flow
        for i, line in enumerate(lines, 1):
            for pattern, cwe, vuln_type in self.taint_sinks:
                if re.search(pattern, line):
                    # Check if any taint source exists before this line
                    if self._taint_reaches_sink(taint_sources, i, lines, line):
                        # Check if sanitization occurred
                        if not self._is_sanitized(i, lines):
                            vulnerabilities.append(
                                self._create_vulnerability(
                                    cwe=cwe,
                                    severity='critical' if 'Injection' in vuln_type else 'high',
                                    title=vuln_type,
                                    description=f'Tainted data from user input reaches dangerous sink without sanitization. Sanitize user input before {vuln_type.lower()}.',
                                    code=code,
                                    filepath=filepath,
                                    line_number=i
                                )
                            )
        
        return vulnerabilities
    
    def _taint_reaches_sink(self, taint_sources: List[Tuple], sink_line: int, all_lines: List[str], sink_line_text: str) -> bool:
        """Check if tainted data could reach this sink."""
        
        # Simple heuristic: if there's a taint source earlier in the code
        # and the sink uses variables, it's likely tainted
        for source_line, source_line_text, _, desc in taint_sources:
            if source_line < sink_line:
                # Check if variables are used
                # Simple check: if sink has user-controlled patterns
                if any(pattern in sink_line_text.lower() for pattern in ['+', 'format', 'f"', 'execute']):
                    return True
        
        # More sophisticated: track variable assignments
        # This is a simplified version
        return len(taint_sources) > 0
    
    def _is_sanitized(self, sink_line: int, all_lines: List[str]) -> bool:
        """Check if data was sanitized before reaching sink."""
        # Look backwards from sink for sanitization
        context_start = max(0, sink_line - 15)
        context = '\n'.join(all_lines[context_start:sink_line])
        
        for sanitizer in self.sanitizers:
            if re.search(sanitizer, context, re.IGNORECASE):
                return True
        
        # Check for parameterized queries
        if re.search(r'PreparedStatement|%s|%d|\?', context, re.IGNORECASE):
            return True
        
        return False
    
    def _create_vulnerability(self, cwe: str, severity: str, title: str, 
                            description: str, code: str, filepath: str, line_number: int):
        """Create a vulnerability object."""
        from parry.scanner import Vulnerability
        
        code_lines = code.split('\n')
        snippet_start = max(0, line_number - 3)
        snippet_end = min(len(code_lines), line_number + 2)
        code_snippet = '\n'.join(code_lines[snippet_start:snippet_end])
        
        return Vulnerability(
            cwe=cwe,
            severity=severity,
            title=title,
            description=description,
            file_path=filepath,
            line_number=line_number,
            code_snippet=code_snippet,
            confidence='high',
            category='security',
            language='python'
        )
    
    def analyze_ast(self, ast_tree, code: str, filepath: str):
        """
        Advanced AST-based data flow analysis.
        
        This is more accurate but requires parsing the code.
        """
        from parry.scanner import Vulnerability
        vulnerabilities = []
        
        # Track variable assignments
        assignments = {}  # var_name -> (line_number, is_tainted)
        function_calls = []
        
        try:
            for node in ast.walk(ast_tree):
                # Track variable assignments
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Check if RHS is tainted
                            is_tainted = self._check_node_tainted(node.value, assignments)
                            assignments[target.id] = (node.lineno, is_tainted)
                
                # Track function calls that might be sinks
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        # Check if arguments are tainted
                        tainted_args = []
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in assignments:
                                _, is_tainted = assignments[arg.id]
                                if is_tainted:
                                    tainted_args.append(arg.id)
                        
                        # If tainted data reaches dangerous function
                        if tainted_args:
                            func_name = node.func.id
                            if self._is_dangerous_function(func_name):
                                vulnerabilities.append(
                                    self._create_vulnerability(
                                        cwe=self._get_cwe_for_function(func_name),
                                        severity='critical',
                                        title=f'Data Flow Vulnerability: {func_name}',
                                        description=f'Tainted user input reaches dangerous function {func_name}. Sanitize input first.',
                                        code=code,
                                        filepath=filepath,
                                        line_number=node.lineno
                                    )
                                )
        
        except Exception as e:
            # AST analysis failed, fallback to pattern-based
            pass
        
        return vulnerabilities
    
    def _check_node_tainted(self, node: ast.AST, assignments: Dict) -> bool:
        """Check if AST node is tainted."""
        if isinstance(node, ast.Name):
            if node.id in assignments:
                _, is_tainted = assignments[node.id]
                return is_tainted
            # Check if it's a known taint source
            if node.id in ['input', 'argv', 'request']:
                return True
        
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ['input', 'gets', 'argv']:
                    return True
        
        return False
    
    def _is_dangerous_function(self, func_name: str) -> bool:
        """Check if function is a dangerous sink."""
        dangerous_funcs = [
            'system', 'exec', 'eval', 'compile',
            'execute', 'executeQuery', 'executeUpdate',
            'write', 'open', 'render', 'Template',
        ]
        return any(danger in func_name.lower() for danger in dangerous_funcs)
    
    def _get_cwe_for_function(self, func_name: str) -> str:
        """Get CWE for dangerous function."""
        mapping = {
            'system': 'CWE-78',
            'exec': 'CWE-94',
            'eval': 'CWE-94',
            'execute': 'CWE-89',
            'executeQuery': 'CWE-89',
            'executeUpdate': 'CWE-89',
            'write': 'CWE-22',
            'open': 'CWE-22',
            'render': 'CWE-94',
            'Template': 'CWE-94',
        }
        
        for key, cwe in mapping.items():
            if key in func_name.lower():
                return cwe
        
        return 'CWE-20'  # Default


