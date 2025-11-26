#!/usr/bin/env python3
"""
AST-based Semantic Analysis Engine for Valid8

Provides deep semantic understanding of code beyond regex patterns.
Parses code into Abstract Syntax Trees for context-aware security analysis.
"""

import ast
import sys
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from ..models import Vulnerability


@dataclass
class ASTNode:
    """Represents a node in the Abstract Syntax Tree with security context"""
    node: ast.AST
    line_number: int
    column_offset: int
    source_code: str
    security_context: Dict[str, Any]


@dataclass
class DataFlow:
    """Tracks data flow through the codebase"""
    variable_name: str
    source: ASTNode
    sinks: List[ASTNode]
    transformations: List[ASTNode]
    tainted: bool = False


class ASTAnalyzer:
    """AST-based semantic analyzer for deep code understanding"""

    def __init__(self):
        self.data_flows: Dict[str, DataFlow] = {}
        self.function_calls: Dict[str, List[ASTNode]] = {}
        self.variable_assignments: Dict[str, List[ASTNode]] = {}
        self.imports: Set[str] = set()

    def analyze_file(self, source_code: str, filepath: str) -> List[Vulnerability]:
        """
        Analyze a Python file using AST parsing

        Args:
            source_code: The source code to analyze
            filepath: Path to the file

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []

        try:
            tree = ast.parse(source_code, filename=filepath)
        except SyntaxError:
            # Fallback to regex-based analysis if AST parsing fails
            return vulnerabilities

        # Extract semantic information
        self._extract_imports(tree)
        self._extract_function_calls(tree)
        self._extract_variable_assignments(tree)
        self._build_data_flows(tree, source_code)

        # Analyze for vulnerabilities using semantic understanding
        vulnerabilities.extend(self._analyze_sql_injection(tree, source_code, filepath))
        vulnerabilities.extend(self._analyze_xss_vulnerabilities(tree, source_code, filepath))
        vulnerabilities.extend(self._analyze_command_injection(tree, source_code, filepath))
        vulnerabilities.extend(self._analyze_insecure_random(tree, source_code, filepath))
        vulnerabilities.extend(self._analyze_hardcoded_secrets(tree, source_code, filepath))

        return vulnerabilities

    def _extract_imports(self, tree: ast.AST) -> None:
        """Extract all import statements"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    self.imports.add(f"{module}.{alias.name}")

    def _extract_function_calls(self, tree: ast.AST) -> None:
        """Extract all function calls with context"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if func_name:
                    ast_node = ASTNode(
                        node=node,
                        line_number=getattr(node, 'lineno', 0),
                        column_offset=getattr(node, 'col_offset', 0),
                        source_code=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                        security_context={'function_name': func_name}
                    )

                    if func_name not in self.function_calls:
                        self.function_calls[func_name] = []
                    self.function_calls[func_name].append(ast_node)

    def _extract_variable_assignments(self, tree: ast.AST) -> None:
        """Extract variable assignments with context"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        ast_node = ASTNode(
                            node=node,
                            line_number=getattr(node, 'lineno', 0),
                            column_offset=getattr(node, 'col_offset', 0),
                            source_code=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                            security_context={'variable': var_name}
                        )

                        if var_name not in self.variable_assignments:
                            self.variable_assignments[var_name] = []
                        self.variable_assignments[var_name].append(ast_node)

    def _build_data_flows(self, tree: ast.AST, source_code: str) -> None:
        """Build data flow graphs for taint analysis"""
        # Track user input sources
        user_input_sources = [
            'input', 'raw_input', 'sys.stdin.read', 'sys.stdin.readline',
            'request.args', 'request.form', 'request.data', 'request.json',
            'flask.request', 'django.request', 'fastapi.request'
        ]

        # Find sources of tainted data
        for var_name, assignments in self.variable_assignments.items():
            for assignment in assignments:
                # Check if assignment uses user input
                if self._uses_user_input(assignment.node.value, user_input_sources):
                    if var_name not in self.data_flows:
                        self.data_flows[var_name] = DataFlow(
                            variable_name=var_name,
                            source=assignment,
                            sinks=[],
                            transformations=[],
                            tainted=True
                        )

        # Find sinks where tainted data is used
        dangerous_sinks = [
            'execute', 'raw', 'cursor.execute', 'sqlite3.execute',
            'subprocess.call', 'subprocess.run', 'os.system', 'eval', 'exec',
            'innerHTML', 'outerHTML', 'document.write', 'dangerouslySetInnerHTML'
        ]

        for func_name, calls in self.function_calls.items():
            if any(sink in func_name for sink in dangerous_sinks):
                for call in calls:
                    # Check if call uses tainted variables
                    tainted_vars = self._get_tainted_variables_in_call(call.node)
                    for var in tainted_vars:
                        if var in self.data_flows:
                            self.data_flows[var].sinks.append(call)

    def _uses_user_input(self, node: ast.AST, user_input_sources: List[str]) -> bool:
        """Check if an AST node uses user input"""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_function_name(child.func)
                if func_name and any(source in func_name for source in user_input_sources):
                    return True
            elif isinstance(child, ast.Attribute):
                attr_name = self._get_attribute_name(child)
                if attr_name and any(source in attr_name for source in user_input_sources):
                    return True
        return False

    def _get_tainted_variables_in_call(self, call_node: ast.Call) -> List[str]:
        """Get tainted variables used in a function call"""
        tainted_vars = []
        for arg in call_node.args:
            tainted_vars.extend(self._extract_variables_from_node(arg))

        for keyword in call_node.keywords:
            tainted_vars.extend(self._extract_variables_from_node(keyword.value))

        return [var for var in tainted_vars if var in self.data_flows]

    def _extract_variables_from_node(self, node: ast.AST) -> List[str]:
        """Extract variable names from an AST node"""
        variables = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                variables.append(child.id)
        return variables

    def _get_function_name(self, func_node: ast.AST) -> Optional[str]:
        """Extract function name from function call AST node"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            return self._get_attribute_name(func_node)
        return None

    def _get_attribute_name(self, attr_node: ast.Attribute) -> str:
        """Extract full attribute name (e.g., 'os.system')"""
        if isinstance(attr_node.value, ast.Name):
            return f"{attr_node.value.id}.{attr_node.attr}"
        elif isinstance(attr_node.value, ast.Attribute):
            return f"{self._get_attribute_name(attr_node.value)}.{attr_node.attr}"
        return attr_node.attr

    def _analyze_sql_injection(self, tree: ast.AST, source_code: str, filepath: str) -> List[Vulnerability]:
        """Analyze for SQL injection using AST understanding"""
        vulnerabilities = []

        for var_name, data_flow in self.data_flows.items():
            if not data_flow.tainted:
                continue

            # Check if tainted data flows to SQL execution
            for sink in data_flow.sinks:
                if 'execute' in sink.security_context.get('function_name', ''):
                    # Check for proper parameterization
                    if not self._is_parameterized_query(sink.node):
                        vuln = Vulnerability(
                            category="injection",
                            title="SQL Injection via Tainted Data",
                            description=f"Tainted data from user input flows to SQL execution without proper parameterization",
                            file_path=filepath,
                            line_number=sink.line_number,
                            code_snippet=sink.source_code,
                            severity="HIGH",
                            confidence="HIGH"
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_xss_vulnerabilities(self, tree: ast.AST, source_code: str, filepath: str) -> List[Vulnerability]:
        """Analyze for XSS using AST understanding"""
        vulnerabilities = []

        dangerous_html_sinks = ['innerHTML', 'outerHTML', 'document.write', 'dangerouslySetInnerHTML']

        for var_name, data_flow in self.data_flows.items():
            if not data_flow.tainted:
                continue

            for sink in data_flow.sinks:
                func_name = sink.security_context.get('function_name', '')
                if any(sink_name in func_name for sink_name in dangerous_html_sinks):
                    vuln = Vulnerability(
                        category="xss",
                        title="Cross-Site Scripting via Tainted Data",
                        description=f"Tainted data flows to HTML output without proper sanitization",
                        file_path=filepath,
                        line_number=sink.line_number,
                        code_snippet=sink.source_code,
                        severity="HIGH",
                        confidence="HIGH"
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_command_injection(self, tree: ast.AST, source_code: str, filepath: str) -> List[Vulnerability]:
        """Analyze for command injection using AST understanding"""
        vulnerabilities = []

        command_sinks = ['subprocess.call', 'subprocess.run', 'os.system', 'os.popen', 'eval', 'exec']

        for var_name, data_flow in self.data_flows.items():
            if not data_flow.tainted:
                continue

            for sink in data_flow.sinks:
                func_name = sink.security_context.get('function_name', '')
                if any(sink_name in func_name for sink_name in command_sinks):
                    vuln = Vulnerability(
                        category="injection",
                        title="Command Injection via Tainted Data",
                        description=f"Tainted data flows to command execution",
                        file_path=filepath,
                        line_number=sink.line_number,
                        code_snippet=sink.source_code,
                        severity="CRITICAL",
                        confidence="HIGH"
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_insecure_random(self, tree: ast.AST, source_code: str, filepath: str) -> List[Vulnerability]:
        """Analyze for insecure random number generation"""
        vulnerabilities = []

        # Check for imports of insecure random modules
        insecure_imports = ['random', 'Random']
        for imp in self.imports:
            if any(insecure in imp for insecure in insecure_imports):
                # Check if they're using random for security-critical operations
                for func_name, calls in self.function_calls.items():
                    if 'random' in func_name.lower():
                        for call in calls:
                            vuln = Vulnerability(
                                category="crypto",
                                title="Insecure Random Number Generation",
                                description=f"Using insecure random number generator for potentially security-critical operation",
                                file_path=filepath,
                                line_number=call.line_number,
                                code_snippet=call.source_code,
                                severity="MEDIUM",
                                confidence="MEDIUM"
                            )
                            vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_hardcoded_secrets(self, tree: ast.AST, source_code: str, filepath: str) -> List[Vulnerability]:
        """Analyze for hardcoded secrets using AST understanding"""
        vulnerabilities = []

        secret_keywords = ['password', 'secret', 'key', 'token', 'api_key', 'apikey']

        for var_name, assignments in self.variable_assignments.items():
            for assignment in assignments:
                if isinstance(assignment.node.value, ast.Str):
                    value = assignment.node.value.s
                    # Check if variable name suggests a secret
                    var_lower = var_name.lower()
                    if any(keyword in var_lower for keyword in secret_keywords):
                        vuln = Vulnerability(
                            category="secrets",
                            title="Hardcoded Secret Detected",
                            description=f"Potential hardcoded secret found in variable '{var_name}'",
                            file_path=filepath,
                            line_number=assignment.line_number,
                            code_snippet=assignment.source_code,
                            severity="HIGH",
                            confidence="MEDIUM"
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_parameterized_query(self, call_node: ast.Call) -> bool:
        """Check if SQL query is properly parameterized"""
        # Look for parameterized query patterns
        # This is a simplified check - real implementation would be more sophisticated
        if len(call_node.args) >= 2:
            # Check if second argument looks like parameters
            second_arg = call_node.args[1]
            if isinstance(second_arg, (ast.Tuple, ast.List, ast.Dict)):
                return True
        return False
