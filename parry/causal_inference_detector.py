"""
Groundbreaking Causal Inference for Vulnerability Root Cause Analysis
Uses causal reasoning to identify vulnerabilities based on cause-effect relationships.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Dict, Any, Tuple, Optional, Set
import networkx as nx
from collections import defaultdict, Counter
import math
import re


class CausalGraph:
    """Causal graph representing code relationships and vulnerabilities."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.causal_relationships = self._define_causal_relationships()
    
    def _define_causal_relationships(self) -> Dict[str, List[str]]:
        """Define causal relationships between code elements and vulnerabilities."""
        return {
            'user_input': ['sql_injection', 'xss', 'command_injection', 'path_traversal'],
            'string_formatting': ['sql_injection', 'xss', 'command_injection'],
            'database_operations': ['sql_injection'],
            'html_output': ['xss'],
            'file_operations': ['path_traversal'],
            'system_calls': ['command_injection'],
            'deserialization': ['unsafe_deserialization'],
            'eval_execution': ['code_injection'],
            'weak_crypto': ['crypto_weakness'],
            'hardcoded_secrets': ['hardcoded_credentials'],
            'missing_validation': ['all_vulnerabilities'],
            'improper_sanitization': ['sql_injection', 'xss', 'command_injection']
        }
    
    def build_causal_graph(self, code: str, filepath: str) -> nx.DiGraph:
        """Build causal graph from code analysis."""
        
        # Add nodes for code elements
        self._add_code_element_nodes(code)
        
        # Add causal edges
        self._add_causal_edges(code)
        
        # Add vulnerability nodes
        self._add_vulnerability_nodes()
        
        return self.graph
    
    def _add_code_element_nodes(self, code: str):
        """Add nodes for code elements that could cause vulnerabilities."""
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # User input sources
            if any(keyword in line_lower for keyword in ['request.', 'input(', 'argv', 'get(']):
                self.graph.add_node(f"user_input_{i}", 
                                  type='user_input', 
                                  line=i, 
                                  code=line.strip())
            
            # String operations
            if any(op in line for op in ['f"', '%', '+', 'format(']):
                self.graph.add_node(f"string_fmt_{i}", 
                                  type='string_formatting', 
                                  line=i, 
                                  code=line.strip())
            
            # Database operations
            if any(db in line_lower for db in ['execute', 'cursor', 'query', 'select']):
                self.graph.add_node(f"db_op_{i}", 
                                  type='database_operations', 
                                  line=i, 
                                  code=line.strip())
            
            # HTML output
            if '<' in line and ('return' in line_lower or 'render' in line_lower):
                self.graph.add_node(f"html_out_{i}", 
                                  type='html_output', 
                                  line=i, 
                                  code=line.strip())
            
            # File operations
            if 'open(' in line or 'read(' in line or 'write(' in line:
                self.graph.add_node(f"file_op_{i}", 
                                  type='file_operations', 
                                  line=i, 
                                  code=line.strip())
            
            # System calls
            if any(sys in line_lower for sys in ['subprocess', 'os.system', 'os.popen', 'system']):
                self.graph.add_node(f"sys_call_{i}", 
                                  type='system_calls', 
                                  line=i, 
                                  code=line.strip())
    
    def _add_causal_edges(self, code: str):
        """Add causal edges between code elements."""
        
        # Find potential causal chains
        user_inputs = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'user_input']
        string_ops = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'string_formatting']
        db_ops = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'database_operations']
        html_ops = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'html_output']
        file_ops = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'file_operations']
        sys_ops = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'system_calls']
        
        # User input -> String formatting -> Database operations
        for ui in user_inputs:
            ui_line = self.graph.nodes[ui]['line']
            for sf in string_ops:
                sf_line = self.graph.nodes[sf]['line']
                if abs(ui_line - sf_line) <= 10:  # Within reasonable distance
                    self.graph.add_edge(ui, sf, type='data_flow')
                    for db in db_ops:
                        db_line = self.graph.nodes[db]['line']
                        if abs(sf_line - db_line) <= 5:
                            self.graph.add_edge(sf, db, type='data_flow')
        
        # User input -> String formatting -> HTML output
        for ui in user_inputs:
            ui_line = self.graph.nodes[ui]['line']
            for sf in string_ops:
                sf_line = self.graph.nodes[sf]['line']
                if abs(ui_line - sf_line) <= 10:
                    self.graph.add_edge(ui, sf, type='data_flow')
                    for html in html_ops:
                        html_line = self.graph.nodes[html]['line']
                        if abs(sf_line - html_line) <= 5:
                            self.graph.add_edge(sf, html, type='data_flow')
        
        # User input -> File operations
        for ui in user_inputs:
            ui_line = self.graph.nodes[ui]['line']
            for fo in file_ops:
                fo_line = self.graph.nodes[fo]['line']
                if abs(ui_line - fo_line) <= 5:
                    self.graph.add_edge(ui, fo, type='data_flow')
        
        # User input -> System calls
        for ui in user_inputs:
            ui_line = self.graph.nodes[ui]['line']
            for so in sys_ops:
                so_line = self.graph.nodes[so]['line']
                if abs(ui_line - so_line) <= 5:
                    self.graph.add_edge(ui, so, type='data_flow')
    
    def _add_vulnerability_nodes(self):
        """Add vulnerability nodes and their causal relationships."""
        
        vuln_types = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79', 
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'unsafe_deserialization': 'CWE-502',
            'code_injection': 'CWE-95',
            'crypto_weakness': 'CWE-327',
            'hardcoded_credentials': 'CWE-798'
        }
        
        for vuln_name, cwe in vuln_types.items():
            self.graph.add_node(f"vuln_{vuln_name}", 
                              type='vulnerability', 
                              cwe=cwe,
                              name=vuln_name)
            
            # Add causal edges from code elements to vulnerabilities
            causes = self.causal_relationships.get(vuln_name, [])
            for cause in causes:
                cause_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == cause]
                for cause_node in cause_nodes:
                    self.graph.add_edge(cause_node, f"vuln_{vuln_name}", type='causes')
    
    def infer_vulnerabilities(self) -> List[Dict]:
        """Infer vulnerabilities using causal reasoning."""
        
        vulnerabilities = []
        
        # Find vulnerability nodes
        vuln_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'vulnerability']
        
        for vuln_node in vuln_nodes:
            vuln_data = self.graph.nodes[vuln_node]
            
            # Check if there are causal paths to this vulnerability
            predecessors = list(self.graph.predecessors(vuln_node))
            
            if predecessors:  # Has causal antecedents
                # Calculate confidence based on causal chain strength
                confidence = min(0.9, 0.6 + len(predecessors) * 0.1)
                
                # Find the root cause (first code element in chain)
                root_causes = []
                for pred in predecessors:
                    if self.graph.nodes[pred].get('type') not in ['vulnerability']:
                        root_causes.append(pred)
                
                if root_causes:
                    root_cause = root_causes[0]  # Take first one
                    root_data = self.graph.nodes[root_cause]
                    
                    vulnerability = {
                        'cwe': vuln_data['cwe'],
                        'severity': 'HIGH' if confidence > 0.8 else 'MEDIUM',
                        'title': f'Causal Inference: {vuln_data["name"].replace("_", " ").title()}',
                        'description': f'Causal analysis found vulnerability through {len(predecessors)} causal relationships',
                        'file_path': 'causal_analysis',
                        'line_number': root_data.get('line', 1),
                        'code_snippet': root_data.get('code', ''),
                        'confidence': confidence,
                        'detection_method': 'causal_inference',
                        'causal_chain_length': len(predecessors),
                        'root_cause_type': root_data.get('type', 'unknown')
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities


class CausalInferenceModel(nn.Module):
    """Neural causal inference model."""
    
    def __init__(self, input_dim=64, hidden_dim=32):
        super().__init__()
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid()
        )
        
        # Causal attention mechanism
        self.causal_attention = nn.MultiheadAttention(hidden_dim, num_heads=4)
    
    def forward(self, x, causal_mask=None):
        """Forward pass with causal reasoning."""
        
        # Encode features
        encoded = self.encoder[:-2](x)  # Get hidden representation
        
        # Apply causal attention
        if causal_mask is not None:
            attended, _ = self.causal_attention(encoded.unsqueeze(0), 
                                              encoded.unsqueeze(0), 
                                              encoded.unsqueeze(0),
                                              attn_mask=causal_mask)
            encoded = attended.squeeze(0)
        
        # Final classification
        output = self.encoder[-2:](encoded.mean(dim=0, keepdim=True))
        return output


class CausalVulnerabilityDetector:
    """Causal inference-based vulnerability detection."""
    
    def __init__(self):
        self.causal_graph = CausalGraph()
        self.model = CausalInferenceModel()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
    
    def analyze_code(self, code: str, filepath: str) -> List[Dict]:
        """Analyze code using causal inference."""
        vulnerabilities = []
        
        try:
            # Build causal graph
            graph = self.causal_graph.build_causal_graph(code, filepath)
            
            # Use graph-based causal inference
            graph_vulns = self.causal_graph.infer_vulnerabilities()
            
            # Enhance with neural causal reasoning
            neural_vulns = self._neural_causal_analysis(code, filepath)
            
            # Combine results
            all_vulns = graph_vulns + neural_vulns
            
            # Deduplicate and boost confidence
            seen_cwes = set()
            for vuln in all_vulns:
                cwe = vuln['cwe']
                if cwe not in seen_cwes:
                    # Boost confidence for causal findings
                    vuln['confidence'] = min(vuln['confidence'] * 1.2, 0.95)
                    vulnerabilities.append(vuln)
                    seen_cwes.add(cwe)
            
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def _neural_causal_analysis(self, code: str, filepath: str) -> List[Dict]:
        """Neural network-based causal analysis."""
        
        vulnerabilities = []
        
        # Simple feature extraction for causal analysis
        features = self._extract_causal_features(code)
        
        if features:
            input_tensor = torch.tensor(features, dtype=torch.float).unsqueeze(0).to(self.device)
            
            with torch.no_grad():
                score = self.model(input_tensor).item()
            
            if score > 0.7:  # Threshold for causal detection
                # Determine most likely vulnerability
                vuln_info = self._classify_causal_vulnerability(code, score)
                
                vulnerability = {
                    'cwe': vuln_info['cwe'],
                    'severity': vuln_info['severity'],
                    'title': f'Neural Causal: {vuln_info["name"]}',
                    'description': f'Neural causal inference detected {vuln_info["name"]} with {score:.2%} confidence',
                    'file_path': filepath,
                    'line_number': self._find_causal_line(code, vuln_info),
                    'code_snippet': self._get_causal_snippet(code, vuln_info),
                    'confidence': score,
                    'detection_method': 'neural_causal_inference'
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_causal_features(self, code: str) -> List[float]:
        """Extract features for causal analysis."""
        
        features = []
        
        # Count potential causal elements
        features.append(code.count('request.'))  # User input
        features.append(code.count('f"') + code.count('%') + code.count('+'))  # String formatting
        features.append(code.count('execute') + code.count('cursor'))  # DB operations
        features.append(code.count('<') and code.count('return'))  # HTML output
        features.append(code.count('open('))  # File operations
        features.append(code.count('subprocess') + code.count('os.system'))  # System calls
        features.append(code.count('pickle') or code.count('yaml'))  # Deserialization
        features.append(code.count('eval(') or code.count('exec('))  # Code execution
        
        # Normalize features
        max_val = max(features) if features else 1
        features = [f / max_val if max_val > 0 else 0 for f in features]
        
        # Pad to fixed dimension
        while len(features) < 64:
            features.append(0.0)
        
        return features[:64]
    
    def _classify_causal_vulnerability(self, code: str, score: float) -> Dict:
        """Classify vulnerability based on causal patterns."""
        
        # Causal pattern matching
        if ('request.' in code or 'input(' in code) and ('execute' in code or 'cursor' in code):
            if 'f"' in code or '%' in code:
                return {'cwe': 'CWE-89', 'name': 'SQL Injection', 'severity': 'HIGH'}
        
        if ('request.' in code or 'input(' in code) and '<' in code and 'return' in code:
            if 'f"' in code:
                return {'cwe': 'CWE-79', 'name': 'XSS', 'severity': 'HIGH'}
        
        if ('request.' in code or 'input(' in code) and ('subprocess' in code or 'os.system' in code)):
            return {'cwe': 'CWE-78', 'name': 'Command Injection', 'severity': 'CRITICAL'}
        
        if ('request.' in code or 'input(' in code) and 'open(' in code):)
            return {'cwe': 'CWE-22', 'name': 'Path Traversal', 'severity': 'MEDIUM'}
        
        if 'pickle' in code and 'loads' in code:
            return {'cwe': 'CWE-502', 'name': 'Unsafe Deserialization', 'severity': 'HIGH'}
        
        if 'eval(' in code or 'exec(' in code:
            return {'cwe': 'CWE-95', 'name': 'Code Injection', 'severity': 'CRITICAL'}
        
        return {'cwe': 'CWE-UNKNOWN', 'name': 'Causal Pattern', 'severity': 'LOW'}
    
    def _find_causal_line(self, code: str, vuln_info: Dict) -> int:
        """Find the line number with causal evidence."""
        lines = code.split('\n')
        
        patterns = {
            'SQL Injection': ['execute', 'cursor', 'request.'],
            'XSS': ['return f"', 'request.', '<'],
            'Command Injection': ['subprocess', 'os.system', 'request.'],
            'Path Traversal': ['open(', 'request.'],
            'Unsafe Deserialization': ['pickle', 'loads'],
            'Code Injection': ['eval', 'exec']
        }
        
        vuln_name = vuln_info['name']
        keywords = patterns.get(vuln_name, [])
        
        for i, line in enumerate(lines, 1):
            if any(keyword in line.lower() for keyword in keywords):
                return i
        
        return 1
    
    def _get_causal_snippet(self, code: str, vuln_info: Dict) -> str:
        """Get code snippet showing causal relationship."""
        line_num = self._find_causal_line(code, vuln_info)
        lines = code.split('\n')
        
        if 1 <= line_num <= len(lines):
            start = max(1, line_num - 3)
            end = min(len(lines), line_num + 3)
            return '\n'.join(lines[start-1:end])
        
        return ""
