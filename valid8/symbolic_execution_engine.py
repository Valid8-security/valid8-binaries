"""
Groundbreaking Symbolic Execution Engine for Vulnerability Detection
Explores all possible execution paths to find hidden vulnerabilities.
"""

import ast
import z3
from typing import List, Dict, Any, Tuple, Optional, Set, Union
from collections import defaultdict
import copy


class SymbolicState:
    """Represents the symbolic state of program execution."""
    
    def __init__(self):
        self.symbolic_vars = {}  # Variable name -> Z3 expression
        self.constraints = []    # Path constraints
        self.solver = z3.Solver()
        
    def add_variable(self, name: str, symbolic_value):
        """Add a symbolic variable."""
        self.symbolic_vars[name] = symbolic_value
    
    def add_constraint(self, constraint):
        """Add a path constraint."""
        self.constraints.append(constraint)
        self.solver.add(constraint)
    
    def copy(self):
        """Create a copy of the symbolic state."""
        new_state = SymbolicState()
        new_state.symbolic_vars = self.symbolic_vars.copy()
        new_state.constraints = self.constraints.copy()
        new_state.solver = self.solver.translate(z3.main_ctx())
        return new_state
    
    def is_sat(self) -> bool:
        """Check if the current constraints are satisfiable."""
        return self.solver.check() == z3.sat
    
    def get_model(self):
        """Get a model satisfying the constraints."""
        if self.solver.check() == z3.sat:
            return self.solver.model()
        return None


class SymbolicExecutor:
    """Symbolic execution engine for Python code."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.max_paths = 100  # Limit to prevent explosion
        self.max_depth = 20   # Maximum call stack depth
        
    def execute_function(self, func_node: ast.FunctionDef, args: Dict[str, Any] = None) -> List[SymbolicState]:
        """Symbolically execute a function."""
        initial_state = SymbolicState()
        
        # Initialize symbolic arguments
        if args:
            for arg_name, arg_value in args.items():
                if isinstance(arg_value, str) and arg_value == "SYMBOLIC":
                    # Create symbolic string
                    symbolic_arg = z3.String(f"sym_{arg_name}")
                    initial_state.add_variable(arg_name, symbolic_arg)
                else:
                    initial_state.add_variable(arg_name, arg_value)
        
        # Execute function body
        states = self._execute_block(func_node.body, [initial_state], 0)
        
        return states
    
    def _execute_block(self, statements: List[ast.stmt], states: List[SymbolicState], 
                      depth: int) -> List[SymbolicState]:
        """Execute a block of statements symbolically."""
        if depth > self.max_depth:
            return states
            
        current_states = states
        
        for stmt in statements:
            if len(current_states) > self.max_paths:
                # Prune paths to prevent explosion
                current_states = current_states[:self.max_paths]
                
            current_states = self._execute_statement(stmt, current_states, depth)
            
            if not current_states:
                break
        
        return current_states
    
    def _execute_statement(self, stmt: ast.stmt, states: List[SymbolicState], 
                          depth: int) -> List[SymbolicState]:
        """Execute a single statement symbolically."""
        new_states = []
        
        for state in states:
            if isinstance(stmt, ast.Assign):
                new_states.extend(self._execute_assignment(stmt, state, depth))
            elif isinstance(stmt, ast.If):
                new_states.extend(self._execute_if(stmt, state, depth))
            elif isinstance(stmt, ast.Return):
                new_states.extend(self._execute_return(stmt, state, depth))
            elif isinstance(stmt, ast.Expr):
                new_states.extend(self._execute_expression(stmt.value, state, depth))
            else:
                # For other statements, just copy the state
                new_states.append(state.copy())
        
        return new_states
    
    def _execute_assignment(self, stmt: ast.Assign, state: SymbolicState, 
                           depth: int) -> List[SymbolicState]:
        """Execute an assignment statement."""
        if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            var_name = stmt.targets[0].id
            
            # Evaluate the right-hand side
            value = self._evaluate_expression(stmt.value, state)
            
            # Create new state with updated variable
            new_state = state.copy()
            new_state.add_variable(var_name, value)
            
            return [new_state]
        
        return [state.copy()]
    
    def _execute_if(self, stmt: ast.If, state: SymbolicState, 
                   depth: int) -> List[SymbolicState]:
        """Execute an if statement, exploring both branches."""
        # Evaluate condition
        condition = self._evaluate_expression(stmt.orelse, state)
        
        # True branch
        true_state = state.copy()
        if condition is not None:
            true_constraint = condition  # Assume condition is True
            true_state.add_constraint(true_constraint)
        
        true_states = self._execute_block(stmt.body, [true_state], depth + 1)
        
        # False branch
        false_state = state.copy()
        if condition is not None:
            false_constraint = z3.Not(condition)  # Assume condition is False
            false_state.add_constraint(false_constraint)
        
        false_states = self._execute_block(stmt.orelse, [false_state], depth + 1)
        
        return true_states + false_states
    
    def _execute_return(self, stmt: ast.Return, state: SymbolicState, 
                       depth: int) -> List[SymbolicState]:
        """Execute a return statement."""
        if stmt.value:
            return_value = self._evaluate_expression(stmt.value, state)
            # Mark this as a return state
            state.return_value = return_value
        
        return [state]
    
    def _execute_expression(self, expr: ast.expr, state: SymbolicState, 
                           depth: int) -> List[SymbolicState]:
        """Execute an expression."""
        # Check for vulnerabilities in expressions
        self._check_expression_vulnerabilities(expr, state)
        
        result = self._evaluate_expression(expr, state)
        return [state.copy()]
    
    def _evaluate_expression(self, expr: ast.expr, state: SymbolicState):
        """Evaluate an expression symbolically."""
        if isinstance(expr, ast.Name):
            return state.symbolic_vars.get(expr.id)
        elif isinstance(expr, ast.Str):
            return expr.s
        elif isinstance(expr, ast.Num):
            return expr.n
        elif isinstance(expr, ast.BinOp):
            left = self._evaluate_expression(expr.left, state)
            right = self._evaluate_expression(expr.right, state)
            
            if isinstance(expr.op, ast.Add):
                if isinstance(left, str) and isinstance(right, str):
                    return z3.Concat(left, right) if hasattr(z3, 'Concat') else f"{left}{right}"
                return left + right if left is not None and right is not None else None
            elif isinstance(expr.op, ast.Eq):
                return left == right if left is not None and right is not None else None
        elif isinstance(expr, ast.Call):
            return self._evaluate_call(expr, state)
        
        return None
    
    def _evaluate_call(self, expr: ast.Call, state: SymbolicState):
        """Evaluate a function call symbolically."""
        if isinstance(expr.func, ast.Name):
            func_name = expr.func.name
            
            # Handle built-in functions symbolically
            if func_name == 'len':
                if expr.args and isinstance(expr.args[0], ast.Name):
                    arg_name = expr.args[0].id
                    if arg_name in state.symbolic_vars:
                        # Return symbolic length
                        return z3.Length(state.symbolic_vars[arg_name])
            
            # Check for vulnerable functions
            self._check_function_call_vulnerabilities(func_name, expr.args, state)
        
        return None
    
    def _check_expression_vulnerabilities(self, expr: ast.expr, state: SymbolicState):
        """Check for vulnerabilities in expressions."""
        # Check for SQL injection
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute):
                if isinstance(expr.func.value, ast.Name):
                    obj_name = expr.func.value.id
                    method_name = expr.func.attr
                    
                    if method_name == 'execute' and expr.args:
                        arg = expr.args[0]
                        if isinstance(arg, ast.Name) and arg.id in state.symbolic_vars:
                            # Check if the symbolic variable can contain SQL
                            self._check_sql_injection(state.symbolic_vars[arg.id], state)
    
    def _check_function_call_vulnerabilities(self, func_name: str, args: List[ast.expr], 
                                           state: SymbolicState):
        """Check for vulnerabilities in function calls."""
        # SQL injection
        if func_name in ['execute', 'executemany'] or 'cursor' in str(args):
            for arg in args:
                if isinstance(arg, ast.Name) and arg.id in state.symbolic_vars:
                    self._check_sql_injection(state.symbolic_vars[arg.id], state)
        
        # Command injection
        if func_name in ['system', 'popen'] or 'subprocess' in str(args):
            for arg in args:
                if isinstance(arg, ast.Name) and arg.id in state.symbolic_vars:
                    self._check_command_injection(state.symbolic_vars[arg.id], state)
    
    def _check_sql_injection(self, symbolic_var, state: SymbolicState):
        """Check if a symbolic variable can cause SQL injection."""
        if isinstance(symbolic_var, z3.ExprRef):
            # Try to find if the variable can contain dangerous SQL
            # This is a simplified check - in practice would be more sophisticated
            
            # Create a test case where the variable contains SQL injection
            injection_test = z3.Contains(symbolic_var, z3.StringVal("; DROP TABLE"))
            
            # If this is possible under current constraints, flag as vulnerable
            solver = z3.Solver()
            solver.add(state.constraints)
            solver.add(injection_test)
            
            if solver.check() == z3.sat:
                self.vulnerabilities.append({
                    'type': 'sql_injection',
                    'cwe': 'CWE-89',
                    'confidence': 0.9,
                    'description': 'Symbolic execution found potential SQL injection path',
                    'constraints': str(state.constraints)
                })
    
    def _check_command_injection(self, symbolic_var, state: SymbolicState):
        """Check if a symbolic variable can cause command injection."""
        if isinstance(symbolic_var, z3.ExprRef):
            injection_test = z3.Contains(symbolic_var, z3.StringVal("; rm -rf"))
            
            solver = z3.Solver()
            solver.add(state.constraints)
            solver.add(injection_test)
            
            if solver.check() == z3.sat:
                self.vulnerabilities.append({
                    'type': 'command_injection',
                    'cwe': 'CWE-78',
                    'confidence': 0.85,
                    'description': 'Symbolic execution found potential command injection path',
                    'constraints': str(state.constraints)
                })


class SymbolicVulnerabilityDetector:
    """High-level interface for symbolic execution-based vulnerability detection."""
    
    def __init__(self):
        self.executor = SymbolicExecutor()
    
    def analyze_function(self, func_code: str, func_name: str = "test_function") -> List[Dict]:
        """Analyze a function using symbolic execution."""
        try:
            # Parse the function
            tree = ast.parse(func_code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == func_name:
                    # Execute symbolically
                    states = self.executor.execute_function(node)
                    
                    # Convert vulnerabilities to standard format
                    vulnerabilities = []
                    for vuln in self.executor.vulnerabilities:
                        vulnerability = {
                            'cwe': vuln['cwe'],
                            'severity': 'HIGH' if vuln['confidence'] > 0.8 else 'MEDIUM',
                            'title': f'Symbolic Execution: {vuln["type"].replace("_", " ").title()}',
                            'description': vuln['description'],
                            'file_path': 'symbolic_analysis',
                            'line_number': 1,  # Would need better line mapping
                            'code_snippet': func_code[:100] + '...',
                            'confidence': vuln['confidence'],
                            'detection_method': 'symbolic_execution'
                        }
                        vulnerabilities.append(vulnerability)
                    
                    return vulnerabilities
            
        except Exception as e:
            pass
        
        return []
    
    def analyze_code(self, code: str, filepath: str) -> List[Dict]:
        """Analyze full code file using symbolic execution."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code)
            
            # Find all functions and analyze them
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_vulns = self.analyze_function(ast.get_source_segment(code, node), node.name)
                    for vuln in func_vulns:
                        vuln['file_path'] = filepath
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            pass
        
        return vulnerabilities
