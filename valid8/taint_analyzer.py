"""
Advanced taint analysis for data flow tracking and vulnerability detection.
"""

import ast
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict
from ..language_support.base import Vulnerability


class TaintAnalyzer:
    """Advanced taint analysis for tracking data flow from sources to sinks."""
    
    def __init__(self):
        self.sources = self._get_taint_sources()
        self.sinks = self._get_taint_sinks()
        self.sanitizers = self._get_taint_sanitizers()
        
    def _get_taint_sources(self) -> Dict[str, Dict]:
        """Define taint sources (user input functions)."""
        return {
            'request.args': {'type': 'http_get', 'cwe': 'CWE-20'},
            'request.form': {'type': 'http_post', 'cwe': 'CWE-20'},
            'request.json': {'type': 'http_json', 'cwe': 'CWE-20'},
            'request.data': {'type': 'http_data', 'cwe': 'CWE-20'},
            'request.cookies': {'type': 'http_cookies', 'cwe': 'CWE-20'},
            'request.headers': {'type': 'http_headers', 'cwe': 'CWE-20'},
            'input(': {'type': 'stdin', 'cwe': 'CWE-20'},
            'raw_input(': {'type': 'stdin', 'cwe': 'CWE-20'},
            'sys.argv': {'type': 'command_line', 'cwe': 'CWE-20'},
            'os.environ': {'type': 'environment', 'cwe': 'CWE-20'},
            'open(': {'type': 'file_input', 'cwe': 'CWE-22'},
            'file.read(': {'type': 'file_input', 'cwe': 'CWE-22'},
        }
    
    def _get_taint_sinks(self) -> Dict[str, Dict]:
        """Define taint sinks (dangerous operations)."""
        return {
            # SQL injection sinks
            'cursor.execute': {'type': 'sql', 'cwe': 'CWE-89', 'severity': 'HIGH'},
            'connection.execute': {'type': 'sql', 'cwe': 'CWE-89', 'severity': 'HIGH'},
            'db.execute': {'type': 'sql', 'cwe': 'CWE-89', 'severity': 'HIGH'},
            'sqlite3.connect.execute': {'type': 'sql', 'cwe': 'CWE-89', 'severity': 'HIGH'},
            
            # Command injection sinks
            'subprocess.call': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            'subprocess.run': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            'subprocess.Popen': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            'os.system': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            'os.popen': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            'os.exec': {'type': 'command', 'cwe': 'CWE-78', 'severity': 'CRITICAL'},
            
            # XSS sinks
            'innerHTML': {'type': 'xss', 'cwe': 'CWE-79', 'severity': 'HIGH'},
            'outerHTML': {'type': 'xss', 'cwe': 'CWE-79', 'severity': 'HIGH'},
            'document.write': {'type': 'xss', 'cwe': 'CWE-79', 'severity': 'HIGH'},
            'eval(': {'type': 'code_injection', 'cwe': 'CWE-95', 'severity': 'CRITICAL'},
            'exec(': {'type': 'code_injection', 'cwe': 'CWE-95', 'severity': 'CRITICAL'},
            
            # Path traversal sinks
            'open(': {'type': 'file_access', 'cwe': 'CWE-22', 'severity': 'HIGH'},
            'os.path.join': {'type': 'file_access', 'cwe': 'CWE-22', 'severity': 'HIGH'},
            'os.open': {'type': 'file_access', 'cwe': 'CWE-22', 'severity': 'HIGH'},
            
            # Deserialization sinks
            'pickle.loads': {'type': 'deserialization', 'cwe': 'CWE-502', 'severity': 'HIGH'},
            'pickle.load': {'type': 'deserialization', 'cwe': 'CWE-502', 'severity': 'HIGH'},
            'yaml.load': {'type': 'deserialization', 'cwe': 'CWE-502', 'severity': 'HIGH'},
            'json.loads': {'type': 'deserialization', 'cwe': 'CWE-502', 'severity': 'MEDIUM'},
            
            # Log injection sinks
            'logging.info': {'type': 'log_injection', 'cwe': 'CWE-532', 'severity': 'MEDIUM'},
            'logging.error': {'type': 'log_injection', 'cwe': 'CWE-532', 'severity': 'MEDIUM'},
            'print(': {'type': 'log_injection', 'cwe': 'CWE-532', 'severity': 'LOW'},
        }
    
    def _get_taint_sanitizers(self) -> Dict[str, Dict]:
        """Define taint sanitizers (functions that clean input)."""
        return {
            'html.escape': {'type': 'html_escape', 'effectiveness': 0.9},
            'cgi.escape': {'type': 'html_escape', 'effectiveness': 0.8},
            ' bleach.clean': {'type': 'html_sanitizer', 'effectiveness': 0.95},
            're.escape': {'type': 'regex_escape', 'effectiveness': 0.9},
            'quote': {'type': 'url_quote', 'effectiveness': 0.8},
            'int(': {'type': 'type_cast', 'effectiveness': 0.9},
            'float(': {'type': 'type_cast', 'effectiveness': 0.9},
            'str(': {'type': 'type_cast', 'effectiveness': 0.5},
            'validate_': {'type': 'custom_validator', 'effectiveness': 0.7},
            'sanitize_': {'type': 'custom_sanitizer', 'effectiveness': 0.8},
        }
    
    def analyze_code(self, code: str, filepath: str) -> List[Vulnerability]:
        """Perform comprehensive taint analysis on code."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code, filename=filepath)
            analyzer = TaintFlowAnalyzer(self.sources, self.sinks, self.sanitizers, filepath, code)
            analyzer.visit(tree)
            vulnerabilities = analyzer.vulnerabilities
        except SyntaxError:
            pass
            
        return vulnerabilities


class TaintFlowAnalyzer(ast.NodeVisitor):
    """AST visitor that performs taint flow analysis."""
    
    def __init__(self, sources: Dict, sinks: Dict, sanitizers: Dict, filepath: str, code: str):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.filepath = filepath
        self.code = code
        self.lines = code.split('\n')
        
        # Taint tracking state
        self.tainted_vars: Set[str] = set()
        self.var_taint_levels: Dict[str, float] = {}
        self.function_taint: Dict[str, Set[str]] = defaultdict(set)
        self.vulnerabilities: List[Vulnerability] = []
        
        # Control flow tracking
        self.current_function: Optional[str] = None
        self.scope_stack: List[Dict] = [{}]
        
    def visit_FunctionDef(self, node):
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name
        
        # Check function parameters for taint
        for arg in node.args.args:
            if self._is_tainted_source_arg(arg.arg):
                self.tainted_vars.add(arg.arg)
                self.var_taint_levels[arg.arg] = 0.8
        
        self.scope_stack.append({})
        self.generic_visit(node)
        self.scope_stack.pop()
        self.current_function = old_function
    
    def visit_Assign(self, node):
        """Track variable assignments and taint propagation."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            
            # Check if assignment uses tainted data
            if self._expression_is_tainted(node.value):
                self.tainted_vars.add(var_name)
                taint_level = self._calculate_taint_level(node.value)
                self.var_taint_levels[var_name] = taint_level
                
                # Check if this might be sanitization
                if self._is_sanitizer_call(node.value):
                    # Reduce taint level
                    self.var_taint_levels[var_name] = max(0.1, taint_level * 0.3)
            else:
                # Clean assignment
                if var_name in self.tainted_vars:
                    self.tainted_vars.discard(var_name)
                    self.var_taint_levels.pop(var_name, None)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Analyze function calls for taint sinks."""
        func_name = self._get_full_func_name(node.func)
        
        # Check if this is a sink
        for sink_pattern, sink_info in self.sinks.items():
            if sink_pattern in func_name:
                # Check if any arguments are tainted
                tainted_args = []
                for i, arg in enumerate(node.args):
                    if self._expression_is_tainted(arg):
                        tainted_args.append(i)
                
                if tainted_args:
                    # Found tainted data flowing to sink
                    vuln = Vulnerability(
                        cwe=sink_info['cwe'],
                        severity=sink_info['severity'],
                        title=f"Taint Analysis: {sink_info['type'].replace('_', ' ').title()}",
                        description=f"Tainted data flows from user input to {sink_info['type']} sink",
                        file_path=self.filepath,
                        line_number=getattr(node, 'lineno', 1),
                        code_snippet=self._get_code_snippet(getattr(node, 'lineno', 1)),
                        confidence=min(0.95, max(self.var_taint_levels.values()) if self.var_taint_levels else 0.8)
                    )
                    self.vulnerabilities.append(vuln)
        
        # Check if this is a sanitizer
        if self._is_sanitizer_call(node):
            # This call sanitizes data, but we handle this in assignment analysis
            pass
        
        self.generic_visit(node)
    
    def visit_Return(self, node):
        """Track return values that might be tainted."""
        if self.current_function and self._expression_is_tainted(node.value):
            self.function_taint[self.current_function].update(self._extract_tainted_vars(node.value))
        
        self.generic_visit(node)
    
    def _expression_is_tainted(self, expr) -> bool:
        """Check if an expression contains tainted data."""
        if isinstance(expr, ast.Name):
            return expr.id in self.tainted_vars
        elif isinstance(expr, ast.Call):
            # Check function call arguments
            for arg in expr.args:
                if self._expression_is_tainted(arg):
                    return True
            # Check if function itself is tainted
            func_name = self._get_func_name(expr.func)
            if func_name in self.function_taint:
                return bool(self.function_taint[func_name])
        elif isinstance(expr, ast.BinOp):
            # Binary operations can propagate taint
            return (self._expression_is_tainted(expr.left) or 
                    self._expression_is_tainted(expr.right))
        elif isinstance(expr, ast.Str):
            # String literals with user data patterns
            return self._string_contains_user_data(expr.s)
        elif isinstance(expr, ast.JoinedStr):
            # f-strings can be tainted
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    if self._expression_is_tainted(value.value):
                        return True
        elif isinstance(expr, ast.Attribute):
            # Attribute access might be tainted
            if isinstance(expr.value, ast.Name):
                base_name = expr.value.id
                if base_name in self.tainted_vars:
                    return True
                # Check for known tainted attributes
                full_attr = f"{base_name}.{expr.attr}"
                for source in self.sources:
                    if source in full_attr:
                        return True
        
        return False
    
    def _calculate_taint_level(self, expr) -> float:
        """Calculate the taint level of an expression."""
        if isinstance(expr, ast.Name) and expr.id in self.var_taint_levels:
            return self.var_taint_levels[expr.id]
        elif isinstance(expr, ast.Call):
            # Function calls can modify taint level
            if self._is_sanitizer_call(expr):
                sanitizer = self._get_func_name(expr.func)
                effectiveness = self.sanitizers.get(sanitizer, {}).get('effectiveness', 0.5)
                # Get maximum taint from arguments
                max_taint = 0.0
                for arg in expr.args:
                    if isinstance(arg, ast.Name) and arg.id in self.var_taint_levels:
                        max_taint = max(max_taint, self.var_taint_levels[arg.id])
                return max_taint * (1 - effectiveness)
            else:
                # Regular function call - propagate maximum taint
                max_taint = 0.0
                for arg in expr.args:
                    if isinstance(arg, ast.Name) and arg.id in self.var_taint_levels:
                        max_taint = max(max_taint, self.var_taint_levels[arg.id])
                return max_taint
        elif isinstance(expr, ast.BinOp):
            # Binary operations - take maximum taint
            left_taint = self.var_taint_levels.get(
                expr.left.id if isinstance(expr.left, ast.Name) else 'unknown', 0.0)
            right_taint = self.var_taint_levels.get(
                expr.right.id if isinstance(expr.right, ast.Name) else 'unknown', 0.0)
            return max(left_taint, right_taint)
        
        return 0.5  # Default taint level
    
    def _is_tainted_source_arg(self, arg_name: str) -> bool:
        """Check if a function argument is a known tainted source."""
        # This would be enhanced with call graph analysis
        return False
    
    def _is_sanitizer_call(self, expr) -> bool:
        """Check if expression is a sanitizer function call."""
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr.func)
            return func_name in self.sanitizers
        return False
    
    def _string_contains_user_data(self, string: str) -> bool:
        """Check if string contains user data patterns."""
        # Look for common user data indicators in strings
        indicators = ['{user}', '{input}', '{request}', '%s', '%d']
        return any(indicator in string for indicator in indicators)
    
    def _extract_tainted_vars(self, expr) -> Set[str]:
        """Extract tainted variable names from expression."""
        tainted = set()
        if isinstance(expr, ast.Name) and expr.id in self.tainted_vars:
            tainted.add(expr.id)
        elif isinstance(expr, ast.BinOp):
            tainted.update(self._extract_tainted_vars(expr.left))
            tainted.update(self._extract_tainted_vars(expr.right))
        elif isinstance(expr, (ast.Call, ast.JoinedStr)):
            # More complex extraction would go here
            pass
        return tainted
    
    def _get_full_func_name(self, node) -> str:
        """Get the full function name from an AST node."""
        names = []
        current = node
        while isinstance(current, ast.Attribute):
            names.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            names.insert(0, current.id)
        return '.'.join(names)
    
    def _get_func_name(self, node) -> str:
        """Get function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_full_func_name(node)
        return ""
    
    def _get_code_snippet(self, line_number: int) -> str:
        """Get code snippet around a line number."""
        if 1 <= line_number <= len(self.lines):
            start = max(1, line_number - 2)
            end = min(len(self.lines), line_number + 2)
            return '\n'.join(self.lines[start-1:end])
        return ""
