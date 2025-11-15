# Copyright (c) 2025 Parry Security Labs
# SPDX-License-Identifier: MIT

"""
Control Flow Graph (CFG) Generator

Builds control flow graphs for path-sensitive analysis.
Enables detection of complex vulnerabilities that require understanding
of execution paths and conditional logic.

Key Features:
- AST-based CFG construction
- Branch tracking (if/else, loops, try/except)
- Path enumeration for reachability analysis
- Dead code detection
- Unreachable path identification
"""

import ast
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Types of CFG nodes"""
    ENTRY = "entry"
    EXIT = "exit"
    STATEMENT = "statement"
    CONDITION = "condition"
    BRANCH = "branch"
    LOOP = "loop"
    FUNCTION_CALL = "function_call"
    RETURN = "return"
    EXCEPTION = "exception"


@dataclass
class CFGNode:
    """Node in the control flow graph"""
    id: int
    node_type: NodeType
    code: str
    line_number: int
    ast_node: Optional[ast.AST] = None
    successors: List['CFGNode'] = field(default_factory=list)
    predecessors: List['CFGNode'] = field(default_factory=list)
    dominators: Set['CFGNode'] = field(default_factory=set)
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        return isinstance(other, CFGNode) and self.id == other.id


@dataclass
class ControlFlowPath:
    """Represents a path through the CFG"""
    nodes: List[CFGNode]
    conditions: List[Tuple[str, bool]]  # (condition_code, branch_taken)
    is_feasible: bool = True
    
    def __repr__(self):
        lines = [f"Line {n.line_number}" for n in self.nodes]
        return f"Path: {' → '.join(lines)}"


class ControlFlowGraph:
    """
    Control Flow Graph for path-sensitive analysis
    
    Usage:
        cfg = ControlFlowGraph(code, filepath)
        paths = cfg.get_all_paths(max_depth=50)
        
        # Check if tainted input reaches sink
        for path in paths:
            if cfg.path_connects(path, source_node, sink_node):
                # Potential vulnerability
    """
    
    def __init__(self, code: str, filepath: str):
        self.code = code
        self.filepath = filepath
        self.nodes: List[CFGNode] = []
        self.entry_node: Optional[CFGNode] = None
        self.exit_node: Optional[CFGNode] = None
        self.next_node_id = 0
        
        # Build CFG from AST
        try:
            tree = ast.parse(code)
            self._build_cfg(tree)
            self._compute_dominators()
        except SyntaxError as e:
            # Invalid Python, create empty CFG
            pass
    
    def _build_cfg(self, tree: ast.AST):
        """Build CFG from AST"""
        # Create entry and exit nodes
        self.entry_node = self._create_node(NodeType.ENTRY, "ENTRY", 0)
        self.exit_node = self._create_node(NodeType.EXIT, "EXIT", 0)
        
        # Process module body
        if isinstance(tree, ast.Module):
            current = self.entry_node
            for stmt in tree.body:
                current = self._process_statement(stmt, current)
            
            # Connect last statement to exit
            if current:
                self._add_edge(current, self.exit_node)
    
    def _create_node(self, node_type: NodeType, code: str, line_number: int, ast_node: Optional[ast.AST] = None) -> CFGNode:
        """Create a new CFG node"""
        node = CFGNode(
            id=self.next_node_id,
            node_type=node_type,
            code=code,
            line_number=line_number,
            ast_node=ast_node
        )
        self.next_node_id += 1
        self.nodes.append(node)
        return node
    
    def _add_edge(self, from_node: CFGNode, to_node: CFGNode):
        """Add edge between nodes"""
        if to_node not in from_node.successors:
            from_node.successors.append(to_node)
        if from_node not in to_node.predecessors:
            to_node.predecessors.append(from_node)
    
    def _process_statement(self, stmt: ast.AST, current: CFGNode) -> CFGNode:
        """Process a statement and return next node"""
        
        if isinstance(stmt, ast.If):
            return self._process_if(stmt, current)
        elif isinstance(stmt, (ast.While, ast.For)):
            return self._process_loop(stmt, current)
        elif isinstance(stmt, ast.Try):
            return self._process_try(stmt, current)
        elif isinstance(stmt, ast.Return):
            return self._process_return(stmt, current)
        elif isinstance(stmt, ast.FunctionDef):
            return self._process_function(stmt, current)
        else:
            # Simple statement
            code = ast.unparse(stmt) if hasattr(ast, 'unparse') else ast.dump(stmt)
            node = self._create_node(
                NodeType.STATEMENT,
                code,
                getattr(stmt, 'lineno', 0),
                stmt
            )
            self._add_edge(current, node)
            return node
    
    def _process_if(self, stmt: ast.If, current: CFGNode) -> CFGNode:
        """Process if statement (branching)"""
        # Create condition node
        condition_code = ast.unparse(stmt.test) if hasattr(ast, 'unparse') else ast.dump(stmt.test)
        condition_node = self._create_node(
            NodeType.CONDITION,
            f"if {condition_code}",
            stmt.lineno,
            stmt
        )
        self._add_edge(current, condition_node)
        
        # Process true branch
        true_branch = condition_node
        for s in stmt.body:
            true_branch = self._process_statement(s, true_branch)
        
        # Process false branch (else/elif)
        false_branch = condition_node
        if stmt.orelse:
            for s in stmt.orelse:
                false_branch = self._process_statement(s, false_branch)
        
        # Merge point
        merge_node = self._create_node(NodeType.STATEMENT, "merge", stmt.lineno)
        self._add_edge(true_branch, merge_node)
        self._add_edge(false_branch, merge_node)
        
        return merge_node
    
    def _process_loop(self, stmt: ast.AST, current: CFGNode) -> CFGNode:
        """Process loop (while/for)"""
        # Create loop header
        if isinstance(stmt, ast.While):
            condition = ast.unparse(stmt.test) if hasattr(ast, 'unparse') else ast.dump(stmt.test)
            loop_header = self._create_node(
                NodeType.LOOP,
                f"while {condition}",
                stmt.lineno,
                stmt
            )
        else:  # For loop
            target = ast.unparse(stmt.target) if hasattr(ast, 'unparse') else ast.dump(stmt.target)
            iter_expr = ast.unparse(stmt.iter) if hasattr(ast, 'unparse') else ast.dump(stmt.iter)
            loop_header = self._create_node(
                NodeType.LOOP,
                f"for {target} in {iter_expr}",
                stmt.lineno,
                stmt
            )
        
        self._add_edge(current, loop_header)
        
        # Process loop body
        loop_body = loop_header
        for s in stmt.body:
            loop_body = self._process_statement(s, loop_body)
        
        # Back edge to loop header
        self._add_edge(loop_body, loop_header)
        
        # Exit loop (loop header to after loop)
        after_loop = self._create_node(NodeType.STATEMENT, "after loop", stmt.lineno)
        self._add_edge(loop_header, after_loop)
        
        return after_loop
    
    def _process_try(self, stmt: ast.Try, current: CFGNode) -> CFGNode:
        """Process try/except"""
        # Try block
        try_node = self._create_node(NodeType.STATEMENT, "try", stmt.lineno, stmt)
        self._add_edge(current, try_node)
        
        try_end = try_node
        for s in stmt.body:
            try_end = self._process_statement(s, try_end)
        
        # Exception handlers
        merge_node = self._create_node(NodeType.STATEMENT, "after try", stmt.lineno)
        self._add_edge(try_end, merge_node)
        
        for handler in stmt.handlers:
            handler_node = self._create_node(
                NodeType.EXCEPTION,
                f"except {ast.unparse(handler.type) if handler.type and hasattr(ast, 'unparse') else 'Exception'}",
                handler.lineno,
                handler
            )
            self._add_edge(try_node, handler_node)
            
            handler_end = handler_node
            for s in handler.body:
                handler_end = self._process_statement(s, handler_end)
            
            self._add_edge(handler_end, merge_node)
        
        return merge_node
    
    def _process_return(self, stmt: ast.Return, current: CFGNode) -> CFGNode:
        """Process return statement"""
        value = ast.unparse(stmt.value) if stmt.value and hasattr(ast, 'unparse') else ""
        return_node = self._create_node(
            NodeType.RETURN,
            f"return {value}",
            stmt.lineno,
            stmt
        )
        self._add_edge(current, return_node)
        self._add_edge(return_node, self.exit_node)
        return return_node
    
    def _process_function(self, stmt: ast.FunctionDef, current: CFGNode) -> CFGNode:
        """Process function definition"""
        func_node = self._create_node(
            NodeType.STATEMENT,
            f"def {stmt.name}(...)",
            stmt.lineno,
            stmt
        )
        self._add_edge(current, func_node)
        
        # For now, don't recurse into function body
        # In a more sophisticated implementation, we'd create separate CFGs per function
        
        return func_node
    
    def _compute_dominators(self):
        """Compute dominator sets for each node"""
        if not self.entry_node:
            return
        
        # Initialize: entry dominates only itself
        self.entry_node.dominators = {self.entry_node}
        
        # All other nodes: dominated by everything initially
        for node in self.nodes:
            if node != self.entry_node:
                node.dominators = set(self.nodes)
        
        # Iterate until fixed point
        changed = True
        while changed:
            changed = False
            for node in self.nodes:
                if node == self.entry_node:
                    continue
                
                # dom(n) = {n} ∪ (∩ dom(p) for all predecessors p)
                new_dom = {node}
                if node.predecessors:
                    pred_doms = [set(p.dominators) for p in node.predecessors]
                    new_dom = new_dom.union(set.intersection(*pred_doms))
                
                if new_dom != node.dominators:
                    node.dominators = new_dom
                    changed = True
    
    def get_all_paths(self, max_depth: int = 50) -> List[ControlFlowPath]:
        """
        Get all paths from entry to exit (up to max_depth)
        
        Used for path-sensitive analysis
        """
        if not self.entry_node or not self.exit_node:
            return []
        
        paths = []
        
        def dfs(node: CFGNode, visited: List[CFGNode], conditions: List[Tuple[str, bool]]):
            if len(visited) > max_depth:
                return
            
            if node == self.exit_node:
                paths.append(ControlFlowPath(visited.copy(), conditions.copy()))
                return
            
            if node in visited and node.node_type == NodeType.LOOP:
                # Already in loop, limit iterations
                return
            
            for successor in node.successors:
                new_conditions = conditions.copy()
                
                # Track branch taken
                if node.node_type == NodeType.CONDITION:
                    # Determine which branch
                    is_true_branch = (successor in node.successors[:len(node.successors)//2])
                    new_conditions.append((node.code, is_true_branch))
                
                dfs(successor, visited + [successor], new_conditions)
        
        dfs(self.entry_node, [self.entry_node], [])
        return paths
    
    def path_connects(self, path: ControlFlowPath, source_line: int, sink_line: int) -> bool:
        """Check if a path connects source to sink"""
        source_seen = False
        for node in path.nodes:
            if node.line_number == source_line:
                source_seen = True
            if source_seen and node.line_number == sink_line:
                return True
        return False
    
    def find_unreachable_code(self) -> List[CFGNode]:
        """Find nodes unreachable from entry"""
        if not self.entry_node:
            return []
        
        reachable = set()
        
        def dfs(node: CFGNode):
            if node in reachable:
                return
            reachable.add(node)
            for successor in node.successors:
                dfs(successor)
        
        dfs(self.entry_node)
        
        return [node for node in self.nodes if node not in reachable and node.node_type != NodeType.EXIT]
    
    def to_dot(self) -> str:
        """Export CFG to DOT format for visualization"""
        lines = ["digraph CFG {"]
        lines.append("  node [shape=box];")
        
        for node in self.nodes:
            label = f"{node.id}: {node.node_type.value}\\n{node.code[:30]}"
            shape = "ellipse" if node.node_type == NodeType.CONDITION else "box"
            lines.append(f'  {node.id} [label="{label}", shape={shape}];')
        
        for node in self.nodes:
            for successor in node.successors:
                lines.append(f"  {node.id} -> {successor.id};")
        
        lines.append("}")
        return "\n".join(lines)


def visualize_cfg(code: str, filepath: str, output_path: str = "cfg.dot"):
    """
    Generate CFG visualization
    
    Usage:
        visualize_cfg(code, "example.py", "cfg.dot")
        # Then: dot -Tpng cfg.dot -o cfg.png
    """
    cfg = ControlFlowGraph(code, filepath)
    dot = cfg.to_dot()
    
    with open(output_path, 'w') as f:
        f.write(dot)
    
    print(f"CFG written to {output_path}")
    print("To visualize: dot -Tpng cfg.dot -o cfg.png")
    
    return cfg
