"""
Tree-sitter based AST analysis for advanced vulnerability detection.
"""

import ast
from typing import List, Dict, Any, Set

class TreeSitterAnalyzer:
    """Advanced AST analysis using Python's ast module (tree-sitter compatible)."""
    
    def analyze_code(self, code: str, filepath: str) -> List[Dict]:
        """Analyze Python code using AST parsing."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code, filename=filepath)
            analyzer = ASTVulnerabilityAnalyzer(filepath, code)
            analyzer.visit(tree)
            vulnerabilities = analyzer.vulnerabilities
        except SyntaxError:
            # If code has syntax errors, we can't analyze it
            pass
            
        return vulnerabilities

class ASTVulnerabilityAnalyzer(ast.NodeVisitor):
    """AST visitor that detects vulnerabilities."""
    
    def __init__(self, filepath: str, code: str):
        self.filepath = filepath
        self.code = code
        self.lines = code.splitlines()
        self.vulnerabilities: List[Dict] = []
        self.current_function: str = ""
        self.imports: Set[str] = set()
        self.variables: Dict[str, Any] = {}
        
    def visit_Import(self, node: ast.Import):
        """Track imports for vulnerability analysis."""
        for alias in node.names:
            self.imports.add(alias.name.split('.')[0])
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track from imports."""
        if node.module:
            self.imports.add(node.module.split('.')[0])
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_Assign(self, node: ast.Assign):
        """Analyze assignments for vulnerabilities."""
        # Check for hardcoded secrets
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id.lower()
            if isinstance(node.value, ast.Str):
                value = node.value.s
                # Check for API keys
                if 'api' in var_name and len(str(value)) > 20:
                    self._add_vulnerability(
                        "CWE-798", "HIGH", "Hardcoded API key",
                        f"Potential hardcoded API key in variable '{node.targets[0].id}'",
                        node.lineno, self._get_code_snippet(node.lineno)
                    )
                # Check for passwords
                elif 'password' in var_name or 'passwd' in var_name:
                    self._add_vulnerability(
                        "CWE-798", "HIGH", "Hardcoded password",
                        f"Hardcoded password in variable '{node.targets[0].id}'",
                        node.lineno, self._get_code_snippet(node.lineno)
                    )
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Analyze function calls for vulnerabilities."""
        # Check for SQL injection
        if self._is_sql_call(node):
            self._check_sql_injection(node)
        
        # Check for command injection
        if self._is_command_call(node):
            self._check_command_injection(node)
            
        # Check for unsafe deserialization
        if self._is_deserialization_call(node):
            self._add_vulnerability(
                "CWE-502", "HIGH", "Unsafe deserialization",
                "Potential unsafe deserialization detected",
                node.lineno, self._get_code_snippet(node.lineno)
            )
        
        self.generic_visit(node)
    
    def _is_sql_call(self, node: ast.Call) -> bool:
        """Check if this is a SQL-related call."""
        if isinstance(node.func, ast.Attribute):
            func_name = self._get_full_func_name(node.func)
            return any(sql_func in func_name.lower() for sql_func in [
                'execute', 'executemany', 'cursor.execute', 'connection.execute'
            ])
        return False
    
    def _is_command_call(self, node: ast.Call) -> bool:
        """Check if this is a command execution call."""
        if isinstance(node.func, ast.Attribute):
            func_name = self._get_full_func_name(node.func)
            return any(cmd_func in func_name.lower() for cmd_func in [
                'subprocess.call', 'subprocess.run', 'subprocess.popen',
                'os.system', 'os.popen', 'os.exec'
            ])
        return False
    
    def _is_deserialization_call(self, node: ast.Call) -> bool:
        """Check if this is a deserialization call."""
        if isinstance(node.func, ast.Attribute):
            func_name = self._get_full_func_name(node.func)
            return any(ser_func in func_name.lower() for ser_func in [
                'pickle.load', 'pickle.loads', 'yaml.load', 'yaml.safe_load',
                'json.loads', 'marshal.load'
            ])
        return False
    
    def _check_sql_injection(self, node: ast.Call):
        """Check for SQL injection vulnerabilities."""
        if len(node.args) > 0:
            arg = node.args[0]
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                # String formatting with % operator
                self._add_vulnerability(
                    "CWE-89", "HIGH", "SQL injection via string formatting",
                    "Potential SQL injection using string formatting",
                    node.lineno, self._get_code_snippet(node.lineno)
                )
            elif isinstance(arg, ast.JoinedStr):
                # f-string usage
                self._add_vulnerability(
                    "CWE-89", "HIGH", "SQL injection via f-string",
                    "Potential SQL injection using f-string formatting",
                    node.lineno, self._get_code_snippet(node.lineno)
                )
    
    def _check_command_injection(self, node: ast.Call):
        """Check for command injection vulnerabilities."""
        if len(node.args) > 0:
            arg = node.args[0]
            if isinstance(arg, ast.JoinedStr):
                self._add_vulnerability(
                    "CWE-78", "CRITICAL", "Command injection via f-string",
                    "Potential command injection using f-string",
                    node.lineno, self._get_code_snippet(node.lineno)
                )
    
    def _get_full_func_name(self, node: ast.Attribute) -> str:
        """Get the full function name from an attribute node."""
        names = []
        current = node
        while isinstance(current, ast.Attribute):
            names.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            names.insert(0, current.id)
        return '.'.join(names)
    
    def _get_code_snippet(self, line_number: int) -> str:
        """Get code snippet around a line number."""
        if 1 <= line_number <= len(self.lines):
            start = max(1, line_number - 2)
            end = min(len(self.lines), line_number + 2)
            return "\n".join(self.lines[start-1:end])
        return ""
    
    def _add_vulnerability(self, cwe: str, severity: str, title: str, 
                          description: str, line_number: int, code_snippet: str):
        """Add a vulnerability finding."""
        vuln = {
            'cwe': cwe,
            'severity': severity,
            'title': f"AST: {title}",
            'description': description,
            'file_path': self.filepath,
            'line_number': line_number,
            'code_snippet': code_snippet or "",
            'confidence': 0.9
        }
        self.vulnerabilities.append(vuln)
