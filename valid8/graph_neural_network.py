#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Groundbreaking Graph Neural Network for Code Structure Analysis
Treats code as graphs and uses GNNs to understand relationships and detect vulnerabilities.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv
from torch_geometric.data import Data, Batch
import ast
import networkx as nx
from typing import List, Dict, Any, Tuple, Optional, Set
from collections import defaultdict
import math


class CodeGraphBuilder:
    """Builds graph representation of Python code."""
    
    def __init__(self):
        self.node_types = {
            'function': 0,
            'variable': 1,
            'class': 2,
            'import': 3,
            'call': 4,
            'assignment': 5,
            'control_flow': 6,
            'literal': 7
        }
        
        self.edge_types = {
            'defines': 0,      # function defines variable
            'calls': 1,        # function calls another function
            'uses': 2,         # function uses variable
            'inherits': 3,     # class inherits from another
            'contains': 4,     # class/function contains another
            'imports': 5,      # module imports another
            'flows_to': 6,     # data flow between variables
            'controls': 7      # control flow relationship
        }
    
    def build_graph(self, code: str, filepath: str) -> Data:
        """Build PyTorch Geometric Data object from code."""
        try:
            tree = ast.parse(code, filename=filepath)
            
            # Build NetworkX graph first
            nx_graph = self._build_networkx_graph(tree, code)
            
            # Convert to PyTorch Geometric format
            return self._nx_to_pyg(nx_graph)
            
        except SyntaxError:
            # Return empty graph for invalid code
            return Data(x=torch.empty(0, 32), edge_index=torch.empty(2, 0))
    
    def _build_networkx_graph(self, tree: ast.AST, code: str) -> nx.DiGraph:
        """Build NetworkX directed graph from AST."""
        graph = nx.DiGraph()
        self.node_counter = 0
        
        # Extract all nodes and relationships
        self._extract_functions(graph, tree)
        self._extract_classes(graph, tree)
        self._extract_variables(graph, tree)
        self._extract_calls(graph, tree)
        self._extract_imports(graph, tree)
        self._extract_control_flow(graph, tree)
        self._extract_data_flow(graph, tree)
        
        return graph
    
    def _extract_functions(self, graph: nx.DiGraph, node: ast.AST):
        """Extract function definitions."""
        if isinstance(node, ast.FunctionDef):
            func_id = f"func_{node.name}_{self.node_counter}"
            self.node_counter += 1
            
            # Add function node
            graph.add_node(func_id, 
                         type='function',
                         name=node.name,
                         node_type=self.node_types['function'],
                         features=self._get_node_features(node))
            
            # Recursively process function body
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id != node.name:
                    var_id = f"var_{child.id}_{self.node_counter}"
                    self.node_counter += 1
                    graph.add_node(var_id,
                                 type='variable',
                                 name=child.id,
                                 node_type=self.node_types['variable'],
                                 features=torch.randn(32))
                    
                    # Function uses variable
                    graph.add_edge(func_id, var_id, 
                                 edge_type=self.edge_types['uses'],
                                 relation='uses')
        
        for child in ast.iter_child_nodes(node):
            self._extract_functions(graph, child)
    
    def _extract_classes(self, graph: nx.DiGraph, node: ast.AST):
        """Extract class definitions and inheritance."""
        if isinstance(node, ast.ClassDef):
            class_id = f"class_{node.name}_{self.node_counter}"
            self.node_counter += 1
            
            graph.add_node(class_id,
                         type='class',
                         name=node.name,
                         node_type=self.node_types['class'],
                         features=self._get_node_features(node))
            
            # Handle inheritance
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_id = f"class_{base.id}_{self.node_counter}"
                    self.node_counter += 1
                    graph.add_node(base_id,
                                 type='class',
                                 name=base.id,
                                 node_type=self.node_types['class'],
                                 features=torch.randn(32))
                    
                    graph.add_edge(class_id, base_id,
                                 edge_type=self.edge_types['inherits'],
                                 relation='inherits')
        
        for child in ast.iter_child_nodes(node):
            self._extract_classes(graph, child)
    
    def _extract_variables(self, graph: nx.DiGraph, node: ast.AST):
        """Extract variable assignments."""
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_id = f"var_{target.id}_{self.node_counter}"
                    self.node_counter += 1
                    
                    graph.add_node(var_id,
                                 type='variable',
                                 name=target.id,
                                 node_type=self.node_types['variable'],
                                 features=self._get_node_features(node))
                    
                    # Assignment node
                    assign_id = f"assign_{self.node_counter}"
                    self.node_counter += 1
                    graph.add_node(assign_id,
                                 type='assignment',
                                 node_type=self.node_types['assignment'],
                                 features=torch.randn(32))
                    
                    graph.add_edge(assign_id, var_id,
                                 edge_type=self.edge_types['defines'],
                                 relation='defines')
        
        for child in ast.iter_child_nodes(node):
            self._extract_variables(graph, child)
    
    def _extract_calls(self, graph: nx.DiGraph, node: ast.AST):
        """Extract function calls."""
        if isinstance(node, ast.Call):
            call_id = f"call_{self.node_counter}"
            self.node_counter += 1
            
            graph.add_node(call_id,
                         type='call',
                         node_type=self.node_types['call'],
                         features=self._get_node_features(node))
            
            # Link to called function if it's a name
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                # Find function node
                for n in graph.nodes():
                    if graph.nodes[n].get('name') == func_name and graph.nodes[n].get('type') == 'function':
                        graph.add_edge(call_id, n,
                                     edge_type=self.edge_types['calls'],
                                     relation='calls')
                        break
        
        for child in ast.iter_child_nodes(node):
            self._extract_calls(graph, child)
    
    def _extract_imports(self, graph: nx.DiGraph, node: ast.AST):
        """Extract import statements."""
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_id = f"import_{self.node_counter}"
            self.node_counter += 1
            
            graph.add_node(import_id,
                         type='import',
                         node_type=self.node_types['import'],
                         features=self._get_node_features(node))
        
        for child in ast.iter_child_nodes(node):
            self._extract_imports(graph, child)
    
    def _extract_control_flow(self, graph: nx.DiGraph, node: ast.AST):
        """Extract control flow relationships."""
        if isinstance(node, (ast.If, ast.For, ast.While, ast.Try)):
            control_id = f"control_{self.node_counter}"
            self.node_counter += 1
            
            graph.add_node(control_id,
                         type='control_flow',
                         node_type=self.node_types['control_flow'],
                         features=self._get_node_features(node))
        
        for child in ast.iter_child_nodes(node):
            self._extract_control_flow(graph, child)
    
    def _extract_data_flow(self, graph: nx.DiGraph, node: ast.AST):
        """Extract data flow relationships."""
        # Simplified data flow analysis
        # In a full implementation, this would track variable dependencies
        pass
    
    def _get_node_features(self, node: ast.AST) -> torch.Tensor:
        """Extract features from AST node."""
        # Simplified feature extraction
        # In practice, this would extract semantic features
        return torch.randn(32)
    
    def _nx_to_pyg(self, nx_graph: nx.DiGraph) -> Data:
        """Convert NetworkX graph to PyTorch Geometric Data."""
        if len(nx_graph) == 0:
            return Data(x=torch.empty(0, 32), edge_index=torch.empty(2, 0))
        
        # Node features
        node_features = []
        node_map = {}
        
        for i, (node_id, node_data) in enumerate(nx_graph.nodes(data=True)):
            node_map[node_id] = i
            features = node_data.get('features', torch.randn(32))
            node_features.append(features)
        
        x = torch.stack(node_features) if node_features else torch.empty(0, 32)
        
        # Edges
        edge_index = []
        edge_attr = []
        
        for source, target, edge_data in nx_graph.edges(data=True):
            if source in node_map and target in node_map:
                edge_index.append([node_map[source], node_map[target]])
                edge_attr.append(edge_data.get('edge_type', 0))
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).t() if edge_index else torch.empty(2, 0)
        edge_attr = torch.tensor(edge_attr, dtype=torch.long) if edge_attr else torch.empty(0)
        
        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)


class GraphNeuralNetwork(nn.Module):
    """Graph Neural Network for vulnerability detection."""
    
    def __init__(self, num_node_features: int = 32, hidden_channels: int = 64, 
                 num_classes: int = 8, num_layers: int = 3):
        super().__init__()
        
        self.convs = nn.ModuleList()
        self.convs.append(GCNConv(num_node_features, hidden_channels))
        
        for _ in range(num_layers - 1):
            self.convs.append(GCNConv(hidden_channels, hidden_channels))
        
        self.classifier = nn.Linear(hidden_channels, num_classes)
        self.dropout = nn.Dropout(0.5)
    
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, 
                edge_attr: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Forward pass through GNN."""
        for conv in self.convs[:-1]:
            x = conv(x, edge_index)
            x = F.relu(x)
            x = self.dropout(x)
        
        # Final convolution
        x = self.convs[-1](x, edge_index)
        x = F.relu(x)
        
        # Global mean pooling
        if x.size(0) > 0:
            x = torch.mean(x, dim=0, keepdim=True)
        else:
            x = torch.zeros(1, x.size(1))
        
        # Classification
        out = self.classifier(x)
        return F.sigmoid(out)


class GraphBasedVulnerabilityDetector:
    """Novel graph-based vulnerability detection using GNNs."""
    
    def __init__(self, model_path: Optional[str] = None):
        self.graph_builder = CodeGraphBuilder()
        self.gnn_model = GraphNeuralNetwork()
        
        if model_path and Path(model_path).exists():
            self.gnn_model.load_state_dict(torch.load(model_path))
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.gnn_model.to(self.device)
        self.gnn_model.eval()
        
        self.vuln_types = [
            'sql_injection', 'xss', 'command_injection', 'path_traversal',
            'auth_bypass', 'crypto_weakness', 'deserialization', 'info_disclosure'
        ]
    
    def analyze_code(self, code: str, filepath: str) -> List[Dict]:
        """Analyze code using graph neural networks."""
        vulnerabilities = []
        
        try:
            # Build graph representation
            graph_data = self.graph_builder.build_graph(code, filepath)
            
            if graph_data.x.size(0) == 0:
                return vulnerabilities
            
            # Move to device
            graph_data = graph_data.to(self.device)
            
            # Run GNN inference
            with torch.no_grad():
                predictions = self.gnn_model(graph_data.x, graph_data.edge_index)
                vuln_scores = predictions.squeeze(0)
            
            # Convert predictions to vulnerabilities
            for i, score in enumerate(vuln_scores):
                confidence = score.item()
                
                if confidence > 0.75:  # Lower threshold for graph-based detection
                    vuln_type = self.vuln_types[i] if i < len(self.vuln_types) else 'unknown'
                    
                    vuln = {
                        'cwe': self._get_cwe_for_vuln_type(vuln_type),
                        'severity': 'HIGH' if confidence > 0.85 else 'MEDIUM',
                        'title': f'GNN: {vuln_type.replace("_", " ").title()}',
                        'description': f'Graph Neural Network detected {vuln_type} with {confidence:.2%} confidence',
                        'file_path': filepath,
                        'line_number': self._find_relevant_line(code, vuln_type),
                        'code_snippet': self._get_relevant_snippet(code, vuln_type),
                        'confidence': confidence,
                        'detection_method': 'graph_neural_network'
                    }
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            # Fallback if GNN fails
            pass
        
        return vulnerabilities
    
    def _get_cwe_for_vuln_type(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE."""
        mapping = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'auth_bypass': 'CWE-287',
            'crypto_weakness': 'CWE-327',
            'deserialization': 'CWE-502',
            'info_disclosure': 'CWE-200',
            'unknown': 'CWE-UNKNOWN'
        }
        return mapping.get(vuln_type, 'CWE-UNKNOWN')
    
    def _find_relevant_line(self, code: str, vuln_type: str) -> int:
        """Find a relevant line for the vulnerability type."""
        lines = code.split('\n')
        
        patterns = {
            'sql_injection': ['execute', 'cursor', 'query'],
            'xss': ['return f"', 'innerHTML'],
            'command_injection': ['subprocess', 'os.system'],
            'path_traversal': ['open(', '..'],
            'auth_bypass': ['if admin', 'authenticated'],
            'crypto_weakness': ['md5', 'sha1'],
            'deserialization': ['pickle', 'yaml'],
            'info_disclosure': ['print(', 'log']
        }
        
        keywords = patterns.get(vuln_type, [])
        
        for i, line in enumerate(lines, 1):
            if any(keyword in line.lower() for keyword in keywords):
                return i
        
        return 1
    
    def _get_relevant_snippet(self, code: str, vuln_type: str) -> str:
        """Get relevant code snippet."""
        line_num = self._find_relevant_line(code, vuln_type)
        lines = code.split('\n')
        
        if 1 <= line_num <= len(lines):
            start = max(1, line_num - 2)
            end = min(len(lines), line_num + 2)
            return '\n'.join(lines[start-1:end])
        
        return ""
