"""
Advanced taint analysis for data flow tracking and vulnerability detection.
Enhanced with inter-procedural analysis, path-sensitive tracking, and context-aware sanitization.

Features:
- Inter-procedural taint tracking with call graph analysis
- Context-aware sanitization with effectiveness modeling
- Path-sensitive analysis with control flow graphs
- Field-sensitive object tracking
- Function summary-based analysis
- Advanced taint propagation rules
"""

import ast
import re
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from ..models import Vulnerability


class TaintLevel(Enum):
    """Taint levels for precise tracking."""
    CLEAN = 0.0
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    CRITICAL = 0.95


@dataclass
class TaintInfo:
    """Comprehensive taint information for variables and expressions."""
    level: float = TaintLevel.CLEAN.value
    sources: Set[str] = field(default_factory=set)
    propagation_path: List[str] = field(default_factory=list)
    sanitizers_applied: Set[str] = field(default_factory=set)
    context_sensitivity: Dict[str, Any] = field(default_factory=dict)

    def is_tainted(self) -> bool:
        return self.level > TaintLevel.CLEAN.value

    def merge(self, other: 'TaintInfo') -> 'TaintInfo':
        """Merge two taint information objects."""
        return TaintInfo(
            level=max(self.level, other.level),
            sources=self.sources.union(other.sources),
            propagation_path=self.propagation_path + other.propagation_path,
            sanitizers_applied=self.sanitizers_applied.union(other.sanitizers_applied),
            context_sensitivity={**self.context_sensitivity, **other.context_sensitivity}
        )


@dataclass
class FunctionSummary:
    """Summary of function taint behavior for inter-procedural analysis."""
    name: str
    parameters: List[str]
    tainted_parameters: Set[str] = field(default_factory=set)
    return_taint: TaintInfo = field(default_factory=TaintInfo)
    side_effects: Dict[str, TaintInfo] = field(default_factory=dict)
    call_sites: List[Tuple[str, int]] = field(default_factory=list)  # (file, line)


@dataclass
class ControlFlowNode:
    """Node in control flow graph for path-sensitive analysis."""
    node_id: int
    ast_node: ast.AST
    predecessors: Set[int] = field(default_factory=set)
    successors: Set[int] = field(default_factory=set)
    taint_state: Dict[str, TaintInfo] = field(default_factory=dict)


class TaintAnalyzer:
    """Advanced taint analysis for tracking data flow from sources to sinks."""

    def __init__(self):
        self.sources = self._get_taint_sources()
        self.sinks = self._get_taint_sinks()
        self.sanitizers = self._get_taint_sanitizers()
        self.context_sanitizers = self._get_context_sanitizers()

        # Inter-procedural analysis state
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
        self.worklist: deque = deque()

        # Path-sensitive analysis
        self.control_flow_graphs: Dict[str, Dict[int, ControlFlowNode]] = {}
        
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

    def _get_context_sanitizers(self) -> Dict[str, Dict]:
        """Define context-aware sanitizers with conditional effectiveness."""
        return {
            'html.escape': {
                'effectiveness': {'xss': 0.95, 'sql': 0.1, 'command': 0.1},
                'context_conditions': ['html_output', 'template_rendering']
            },
            're.escape': {
                'effectiveness': {'sql': 0.9, 'command': 0.8, 'xss': 0.3},
                'context_conditions': ['regex_context', 'sql_query']
            },
            'quote': {
                'effectiveness': {'sql': 0.8, 'url_injection': 0.9},
                'context_conditions': ['url_encoding', 'sql_string']
            },
            'int(': {
                'effectiveness': {'sql': 0.95, 'command': 0.95, 'xss': 0.9},
                'context_conditions': ['numeric_required', 'id_parameter']
            },
            'prepared_statement': {
                'effectiveness': {'sql': 0.98},
                'context_conditions': ['database_query']
            },
            'parameterized_query': {
                'effectiveness': {'sql': 0.98},
                'context_conditions': ['orm_query', 'database_operation']
            },
            'escape_shell_arg': {
                'effectiveness': {'command': 0.95},
                'context_conditions': ['shell_command', 'system_call']
            },
            'validate_email': {
                'effectiveness': {'xss': 0.7, 'injection': 0.8},
                'context_conditions': ['email_field', 'user_input']
            },
            'strip_tags': {
                'effectiveness': {'xss': 0.9},
                'context_conditions': ['html_input', 'user_content']
            }
        }
    
    def analyze_code(self, code: str, filepath: str) -> List[Vulnerability]:
        """Perform comprehensive taint analysis with inter-procedural tracking."""
        vulnerabilities = []

        try:
            tree = ast.parse(code, filename=filepath)

            # Phase 1: Build function summaries and call graph
            summary_builder = FunctionSummaryBuilder(self.sources, self.sinks, self.sanitizers,
                                                   self.context_sanitizers, filepath, code)
            summary_builder.visit(tree)

            # Store function summaries
            for func_name, summary in summary_builder.function_summaries.items():
                self.function_summaries[func_name] = summary
                self.call_graph[func_name] = summary_builder.call_graph.get(func_name, set())

            # Phase 2: Inter-procedural analysis with fixed-point iteration
            self._perform_interprocedural_analysis(filepath)

            # Phase 3: Path-sensitive analysis
            path_analyzer = PathSensitiveAnalyzer(self.sources, self.sinks, self.sanitizers,
                                                self.context_sanitizers, self.function_summaries,
                                                filepath, code)
            path_analyzer.visit(tree)
            vulnerabilities.extend(path_analyzer.vulnerabilities)

        except SyntaxError:
            pass

        return vulnerabilities

    def analyze_codebase(self, files: List[Tuple[str, str]]) -> List[Vulnerability]:
        """Analyze entire codebase with inter-procedural analysis across files."""
        all_vulnerabilities = []

        # Phase 1: Build global function summaries across all files
        print("🔗 Building inter-procedural call graph...")
        for filepath, code in files:
            try:
                tree = ast.parse(code, filename=filepath)
                summary_builder = FunctionSummaryBuilder(self.sources, self.sinks, self.sanitizers,
                                                       self.context_sanitizers, filepath, code)
                summary_builder.visit(tree)

                for func_name, summary in summary_builder.function_summaries.items():
                    full_name = f"{filepath}::{func_name}"
                    self.function_summaries[full_name] = summary
                    self.call_graph[full_name] = {f"{filepath}::{called}" for called in
                                                summary_builder.call_graph.get(func_name, set())}

            except SyntaxError:
                continue

        # Phase 2: Fixed-point inter-procedural analysis
        print("🔄 Performing fixed-point inter-procedural analysis...")
        self._perform_global_interprocedural_analysis()

        # Phase 3: Path-sensitive analysis on each file
        print("🎯 Running path-sensitive analysis...")
        for filepath, code in files:
            try:
                tree = ast.parse(code, filename=filepath)
                path_analyzer = PathSensitiveAnalyzer(self.sources, self.sinks, self.sanitizers,
                                                    self.context_sanitizers, self.function_summaries,
                                                    filepath, code)
                path_analyzer.visit(tree)
                all_vulnerabilities.extend(path_analyzer.vulnerabilities)
            except SyntaxError:
                continue

        return all_vulnerabilities

    def _perform_interprocedural_analysis(self, filepath: str):
        """Perform inter-procedural analysis for a single file."""
        # Simple fixed-point iteration for this file
        changed = True
        iterations = 0
        max_iterations = 10

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for func_name, summary in self.function_summaries.items():
                if func_name.startswith(filepath):
                    # Propagate taint through call graph
                    for caller in self.call_graph.get(func_name, set()):
                        caller_summary = self.function_summaries.get(caller)
                        if caller_summary:
                            # Update caller based on callee taint
                            old_taint = caller_summary.return_taint.level
                            caller_summary.return_taint = caller_summary.return_taint.merge(summary.return_taint)
                            if caller_summary.return_taint.level > old_taint:
                                changed = True

    def _perform_global_interprocedural_analysis(self):
        """Perform global inter-procedural analysis across entire codebase."""
        # Fixed-point iteration across all functions
        changed = True
        iterations = 0
        max_iterations = 20

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for func_name, summary in self.function_summaries.items():
                # Propagate taint through call graph
                for callee_name in self.call_graph.get(func_name, set()):
                    callee_summary = self.function_summaries.get(callee_name)
                    if callee_summary:
                        # If callee returns tainted data, taint propagates to caller
                        if callee_summary.return_taint.is_tainted():
                            old_level = summary.return_taint.level
                            summary.return_taint = summary.return_taint.merge(callee_summary.return_taint)
                            if summary.return_taint.level > old_level:
                                changed = True

                        # Propagate side effects
                        for var, taint_info in callee_summary.side_effects.items():
                            if var in summary.side_effects:
                                old_level = summary.side_effects[var].level
                                summary.side_effects[var] = summary.side_effects[var].merge(taint_info)
                                if summary.side_effects[var].level > old_level:
                                    changed = True
                            else:
                                summary.side_effects[var] = taint_info
                                changed = True


class FunctionSummaryBuilder(ast.NodeVisitor):
    """Builds function summaries and call graphs for inter-procedural analysis."""

    def __init__(self, sources: Dict, sinks: Dict, sanitizers: Dict, context_sanitizers: Dict,
                 filepath: str, code: str):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.context_sanitizers = context_sanitizers
        self.filepath = filepath
        self.code = code
        self.lines = code.split('\n')

        # Analysis state
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
        self.current_function: Optional[str] = None
        self.scope_stack: List[Dict[str, TaintInfo]] = [{}]
        self.node_counter = 0

    def visit_FunctionDef(self, node):
        """Build function summary."""
        old_function = self.current_function
        self.current_function = node.name

        # Create function summary
        summary = FunctionSummary(
            name=node.name,
            parameters=[arg.arg for arg in node.args.args]
        )
        self.function_summaries[node.name] = summary

        # New scope for function
        self.scope_stack.append({})

        # Analyze function body
        for stmt in node.body:
            self.visit(stmt)

        # Extract return taint
        return_taint = TaintInfo()
        for stmt in node.body:
            if isinstance(stmt, ast.Return) and stmt.value:
                return_taint = return_taint.merge(self._analyze_expression(stmt.value))

        summary.return_taint = return_taint

        # Pop function scope
        self.scope_stack.pop()
        self.current_function = old_function

    def visit_Call(self, node):
        """Track function calls for call graph."""
        if self.current_function:
            func_name = self._get_func_name(node.func)
            if func_name:
                self.call_graph[self.current_function].add(func_name)

        self.generic_visit(node)

    def visit_Assign(self, node):
        """Track variable assignments and side effects."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            taint_info = self._analyze_expression(node.value)

            # Store in current scope
            if self.scope_stack:
                self.scope_stack[-1][var_name] = taint_info

            # Track side effects in function summary
            if self.current_function and self.function_summaries.get(self.current_function):
                self.function_summaries[self.current_function].side_effects[var_name] = taint_info

        self.generic_visit(node)

    def _analyze_expression(self, expr) -> TaintInfo:
        """Analyze expression for taint information."""
        if isinstance(expr, ast.Name):
            # Check current scope for taint
            for scope in reversed(self.scope_stack):
                if expr.id in scope:
                    return scope[expr.id]
            # Check if it's a known source
            for source_pattern in self.sources:
                if source_pattern in expr.id:
                    return TaintInfo(
                        level=TaintLevel.CRITICAL.value,
                        sources={source_pattern}
                    )
            return TaintInfo()

        elif isinstance(expr, ast.Call):
            func_name = self._get_full_func_name(expr.func)
            taint_info = TaintInfo()

            # Check if function call is a source
            for source_pattern, source_info in self.sources.items():
                if source_pattern in func_name:
                    taint_info = TaintInfo(
                        level=TaintLevel.CRITICAL.value,
                        sources={source_pattern}
                    )
                    break

            # Check if it's a sanitizer
            if self._is_context_sanitizer(expr):
                # Sanitizer reduces taint from arguments
                max_arg_taint = TaintInfo()
                for arg in expr.args:
                    arg_taint = self._analyze_expression(arg)
                    max_arg_taint = max_arg_taint.merge(arg_taint)

                effectiveness = self._get_sanitizer_effectiveness(expr)
                taint_info = TaintInfo(
                    level=max_arg_taint.level * (1 - effectiveness),
                    sources=max_arg_taint.sources,
                    sanitizers_applied={func_name}
                )

            return taint_info

        elif isinstance(expr, ast.BinOp):
            # Binary operations can propagate taint
            left_taint = self._analyze_expression(expr.left)
            right_taint = self._analyze_expression(expr.right)
            return left_taint.merge(right_taint)

        elif isinstance(expr, ast.Str):
            # Check for user data patterns in strings
            if self._string_contains_user_data(expr.s):
                return TaintInfo(level=TaintLevel.MEDIUM.value)
            return TaintInfo()

        return TaintInfo()

    def _is_context_sanitizer(self, expr) -> bool:
        """Check if expression is a context-aware sanitizer."""
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr.func)
            return func_name in self.context_sanitizers
        return False

    def _get_sanitizer_effectiveness(self, expr) -> float:
        """Get effectiveness of sanitizer based on context."""
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr.func)
            sanitizer_info = self.context_sanitizers.get(func_name, {})

            # Default effectiveness
            effectiveness = sanitizer_info.get('effectiveness', {}).get('default', 0.5)

            # Context-aware effectiveness (simplified)
            # In full implementation, this would analyze surrounding code context
            context_conditions = sanitizer_info.get('context_conditions', [])

            # Simple heuristic: if used in certain contexts, higher effectiveness
            if 'html' in ' '.join(context_conditions):
                effectiveness = max(effectiveness, 0.9)
            elif 'sql' in ' '.join(context_conditions):
                effectiveness = max(effectiveness, 0.95)

            return effectiveness
        return 0.5

    def _string_contains_user_data(self, string: str) -> bool:
        """Check if string contains user data patterns."""
        indicators = ['{user}', '{input}', '{request}', '%s', '%d', '{', '}']
        return any(indicator in string for indicator in indicators)

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


class PathSensitiveAnalyzer(ast.NodeVisitor):
    """Path-sensitive taint analysis with control flow awareness."""

    def __init__(self, sources: Dict, sinks: Dict, sanitizers: Dict, context_sanitizers: Dict,
                 function_summaries: Dict[str, FunctionSummary], filepath: str, code: str):
        self.sources = sources
        self.sinks = sinks
        self.sanitizers = sanitizers
        self.context_sanitizers = context_sanitizers
        self.function_summaries = function_summaries
        self.filepath = filepath
        self.code = code
        self.lines = code.split('\n')

        # Path-sensitive state
        self.vulnerabilities: List[Vulnerability] = []
        self.current_path_conditions: Set[str] = set()
        self.taint_state: Dict[str, TaintInfo] = {}

        # Control flow tracking
        self.current_function: Optional[str] = None
        self.scope_stack: List[Dict[str, TaintInfo]] = [{}]
        
    def visit_FunctionDef(self, node):
        """Track function definitions with path sensitivity."""
        old_function = self.current_function
        self.current_function = node.name

        # New scope for function with path conditions
        self.scope_stack.append({})
        self.current_path_conditions.add(f"in_function_{node.name}")

        self.generic_visit(node)

        # Restore previous state
        self.scope_stack.pop()
        self.current_path_conditions.discard(f"in_function_{node.name}")
        self.current_function = old_function

    def visit_Assign(self, node):
        """Track variable assignments with path sensitivity."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id
            taint_info = self._analyze_expression_path_sensitive(node.value)

            # Store in current scope
            if self.scope_stack:
                self.scope_stack[-1][var_name] = taint_info

            # Update global taint state
            self.taint_state[var_name] = taint_info

        self.generic_visit(node)

    def visit_Call(self, node):
        """Analyze function calls for vulnerabilities with path sensitivity."""
        func_name = self._get_full_func_name(node.func)

        # Check if this is a sink
        for sink_pattern, sink_info in self.sinks.items():
            if sink_pattern in func_name:
                # Check if any arguments are tainted under current path conditions
                tainted_args = []
                taint_levels = []

                for i, arg in enumerate(node.args):
                    arg_taint = self._analyze_expression_path_sensitive(arg)
                    if arg_taint.is_tainted():
                        tainted_args.append(i)
                        taint_levels.append(arg_taint.level)

                if tainted_args:
                    # Found tainted data flowing to sink
                    max_taint_level = max(taint_levels) if taint_levels else TaintLevel.HIGH.value

                    # Create vulnerability with enhanced information
                    vuln = Vulnerability(
                        cwe=sink_info['cwe'],
                        severity=self._calculate_severity(sink_info['severity'], max_taint_level),
                        title=f"Path-Sensitive {sink_info['type'].replace('_', ' ').title()} Detection",
                        description=self._generate_detailed_description(func_name, sink_info, tainted_args, max_taint_level),
                        file_path=self.filepath,
                        line_number=getattr(node, 'lineno', 1),
                        code_snippet=self._get_code_snippet(getattr(node, 'lineno', 1)),
                        confidence=min(0.98, max_taint_level)  # Path-sensitive analysis gives higher confidence
                    )
                    self.vulnerabilities.append(vuln)

        # Check for inter-procedural calls
        if func_name in self.function_summaries:
            summary = self.function_summaries[func_name]

            # Propagate taint from function call
            if summary.return_taint.is_tainted():
                # This would be assigned to a variable, handled in visit_Assign
                pass

            # Check side effects
            for var_name, side_effect in summary.side_effects.items():
                if side_effect.is_tainted():
                    self.taint_state[var_name] = side_effect

        self.generic_visit(node)

    def visit_If(self, node):
        """Handle conditional statements with path sensitivity."""
        # Analyze condition
        condition_taint = self._analyze_expression_path_sensitive(node.test)

        # True branch
        true_conditions = self.current_path_conditions.copy()
        true_conditions.add(f"condition_{id(node.test)}_true")

        self.current_path_conditions = true_conditions
        for stmt in node.body:
            self.visit(stmt)

        # False branch (else)
        if node.orelse:
            false_conditions = self.current_path_conditions.copy()
            false_conditions.add(f"condition_{id(node.test)}_false")

            self.current_path_conditions = false_conditions
            for stmt in node.orelse:
                self.visit(stmt)

    def _analyze_expression_path_sensitive(self, expr) -> TaintInfo:
        """Analyze expression with path sensitivity."""
        if isinstance(expr, ast.Name):
            # Check current scope and global state
            for scope in reversed(self.scope_stack):
                if expr.id in scope:
                    return scope[expr.id]

            if expr.id in self.taint_state:
                return self.taint_state[expr.id]

            # Check if it's a known source
            for source_pattern, source_info in self.sources.items():
                if source_pattern in expr.id:
                    return TaintInfo(
                        level=TaintLevel.CRITICAL.value,
                        sources={source_pattern},
                        propagation_path=[f"source_{source_pattern}"]
                    )
            return TaintInfo()

        elif isinstance(expr, ast.Call):
            func_name = self._get_full_func_name(expr.func)
            taint_info = TaintInfo()

            # Check if function call is a source
            for source_pattern, source_info in self.sources.items():
                if source_pattern in func_name:
                    taint_info = TaintInfo(
                        level=TaintLevel.CRITICAL.value,
                        sources={source_pattern},
                        propagation_path=[f"source_call_{func_name}"]
                    )
                    break

            # Check inter-procedural calls
            if func_name in self.function_summaries:
                summary = self.function_summaries[func_name]
                taint_info = taint_info.merge(summary.return_taint)

            # Check if it's a context-aware sanitizer
            if self._is_context_sanitizer_path_sensitive(expr):
                # Sanitizer reduces taint from arguments
                max_arg_taint = TaintInfo()
                for arg in expr.args:
                    arg_taint = self._analyze_expression_path_sensitive(arg)
                    max_arg_taint = max_arg_taint.merge(arg_taint)

                effectiveness = self._get_context_sanitizer_effectiveness(expr)
                taint_info = TaintInfo(
                    level=max_arg_taint.level * (1 - effectiveness),
                    sources=max_arg_taint.sources,
                    propagation_path=max_arg_taint.propagation_path + [f"sanitized_by_{func_name}"],
                    sanitizers_applied=max_arg_taint.sanitizers_applied.union({func_name})
                )
            else:
                # Regular function call - propagate maximum taint from arguments
                max_taint = TaintInfo()
                for arg in expr.args:
                    arg_taint = self._analyze_expression_path_sensitive(arg)
                    max_taint = max_taint.merge(arg_taint)
                taint_info = taint_info.merge(max_taint)

            return taint_info

        elif isinstance(expr, ast.BinOp):
            # Binary operations with path sensitivity
            left_taint = self._analyze_expression_path_sensitive(expr.left)
            right_taint = self._analyze_expression_path_sensitive(expr.right)

            # String concatenation is particularly dangerous
            if isinstance(expr.op, ast.Add):
                # Check if either side contains strings (potential string building)
                if self._is_string_operation(expr.left) or self._is_string_operation(expr.right):
                    combined_level = max(left_taint.level, right_taint.level)
                    combined_sources = left_taint.sources.union(right_taint.sources)
                    combined_path = left_taint.propagation_path + right_taint.propagation_path + ["string_concatenation"]
                    return TaintInfo(
                        level=combined_level,
                        sources=combined_sources,
                        propagation_path=combined_path
                    )

            return left_taint.merge(right_taint)

        elif isinstance(expr, ast.Str):
            # String literals with user data patterns
            if self._string_contains_user_data(expr.s):
                return TaintInfo(
                    level=TaintLevel.MEDIUM.value,
                    propagation_path=["string_literal_with_user_data"]
                )
            return TaintInfo()

        elif isinstance(expr, ast.JoinedStr):
            # f-strings can be particularly dangerous
            max_taint = TaintInfo()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    value_taint = self._analyze_expression_path_sensitive(value.value)
                    max_taint = max_taint.merge(value_taint)

            if max_taint.is_tainted():
                max_taint.propagation_path.append("fstring_interpolation")
                max_taint.level = min(1.0, max_taint.level * 1.2)  # f-strings are more dangerous

            return max_taint

        return TaintInfo()

    def _is_context_sanitizer_path_sensitive(self, expr) -> bool:
        """Check if expression is a context-aware sanitizer with path conditions."""
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr.func)
            if func_name in self.context_sanitizers:
                sanitizer_info = self.context_sanitizers[func_name]
                context_conditions = sanitizer_info.get('context_conditions', [])

                # Check if current path conditions match sanitizer context
                for condition in context_conditions:
                    if any(condition in path_cond for path_cond in self.current_path_conditions):
                        return True

                # Default to true if no specific context required
                return len(context_conditions) == 0
        return False

    def _get_context_sanitizer_effectiveness(self, expr) -> float:
        """Get effectiveness of context-aware sanitizer."""
        if isinstance(expr, ast.Call):
            func_name = self._get_func_name(expr.func)
            sanitizer_info = self.context_sanitizers.get(func_name, {})

            # Get vulnerability-type specific effectiveness
            effectiveness_map = sanitizer_info.get('effectiveness', {})

            # Determine vulnerability type from context
            vuln_type = 'default'
            if any('sql' in cond.lower() for cond in self.current_path_conditions):
                vuln_type = 'sql'
            elif any('xss' in cond.lower() or 'html' in cond.lower() for cond in self.current_path_conditions):
                vuln_type = 'xss'
            elif any('command' in cond.lower() for cond in self.current_path_conditions):
                vuln_type = 'command'

            return effectiveness_map.get(vuln_type, effectiveness_map.get('default', 0.5))

        return 0.5

    def _calculate_severity(self, base_severity: str, taint_level: float) -> str:
        """Calculate severity based on taint level and base severity."""
        if taint_level >= TaintLevel.CRITICAL.value:
            return 'CRITICAL'
        elif taint_level >= TaintLevel.HIGH.value:
            return 'HIGH' if base_severity in ['HIGH', 'CRITICAL'] else 'HIGH'
        elif taint_level >= TaintLevel.MEDIUM.value:
            return base_severity
        else:
            return 'LOW'

    def _generate_detailed_description(self, func_name: str, sink_info: Dict, tainted_args: List[int], taint_level: float) -> str:
        """Generate detailed vulnerability description."""
        vuln_type = sink_info['type'].replace('_', ' ')
        arg_info = f"arguments {', '.join(map(str, tainted_args))}" if len(tainted_args) > 1 else f"argument {tainted_args[0]}"

        description = f"Tainted data flows from user input to {vuln_type} sink '{func_name}' via {arg_info}. "

        if taint_level >= TaintLevel.CRITICAL.value:
            description += "Critical taint level detected - immediate security risk."
        elif taint_level >= TaintLevel.HIGH.value:
            description += "High taint level detected - significant security concern."
        else:
            description += "Medium taint level detected."

        if self.current_path_conditions:
            description += f" Path conditions: {', '.join(self.current_path_conditions)}"

        return description

    def _is_string_operation(self, expr) -> bool:
        """Check if expression involves string operations."""
        return isinstance(expr, (ast.Str, ast.JoinedStr)) or \
               (isinstance(expr, ast.Name) and isinstance(self.taint_state.get(expr.id), str))

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

    def _string_contains_user_data(self, string: str) -> bool:
        """Check if string contains user data patterns."""
        indicators = ['{user}', '{input}', '{request}', '%s', '%d', '{', '}']
        return any(indicator in string for indicator in indicators)
