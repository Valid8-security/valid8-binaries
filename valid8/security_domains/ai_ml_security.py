# Parry (C) by Valid8 Security. Written by Andy Kurapati and Shreyan Mitra
"""
AI/ML Security Detector Module

Detects vulnerabilities specific to AI/ML systems including:
- Prompt injection attacks
- Model poisoning
- Training data poisoning
- Model inversion attacks
- Adversarial examples
- Model extraction
- Federated learning attacks
- Insecure model deserialization

Author: Parry Security Team
Version: 1.0.0
"""

import re
import ast
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class AIMLVulnerability:
    """Represents an AI/ML-specific vulnerability"""
    cwe: str
    title: str
    description: str
    severity: str
    line: int
    column: int
    code: str
    fix: Optional[str] = None
    confidence: float = 0.85


class AIMLSecurityDetector:
    """Detect AI/ML-specific security vulnerabilities"""
    
    # Common LLM API patterns
    LLM_APIS = [
        'openai.ChatCompletion.create',
        'openai.Completion.create',
        'anthropic.Anthropic',
        'cohere.Client',
        'google.generativeai.GenerativeModel',
        'transformers.pipeline',
        'langchain.llms',
        'llamaindex.llms',
    ]
    
    # Unsafe model loading functions
    UNSAFE_MODEL_LOAD = [
        'pickle.load',
        'torch.load',
        'joblib.load',
        'keras.models.load_model',
        'tf.keras.models.load_model',
        'np.load',
    ]
    
    # Framework detection patterns
    ML_FRAMEWORKS = {
        'pytorch': ['torch', 'torchvision', 'torchaudio'],
        'tensorflow': ['tensorflow', 'tf.', 'keras'],
        'sklearn': ['sklearn', 'scikit-learn'],
        'jax': ['jax', 'flax'],
        'huggingface': ['transformers', 'datasets', 'accelerate']
    }
    
    def __init__(self):
        self.vulnerabilities: List[AIMLVulnerability] = []
    
    def detect_all(self, code: str, language: str, filename: str = "") -> List[AIMLVulnerability]:
        """Run all AI/ML security detectors"""
        self.vulnerabilities = []
        
        if language == 'python':
            self._detect_python_aiml_vulns(code, filename)
        elif language in ['javascript', 'typescript']:
            self._detect_js_aiml_vulns(code, filename)
        elif language == 'java':
            self._detect_java_aiml_vulns(code, filename)
        
        return self.vulnerabilities
    
    def _detect_python_aiml_vulns(self, code: str, filename: str):
        """Detect Python AI/ML vulnerabilities"""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to regex-based detection
            self._detect_with_regex(code)
            return
        
        for node in ast.walk(tree):
            self._check_prompt_injection(node, code)
            self._check_model_poisoning(node, code)
            self._check_insecure_model_load(node, code)
            self._check_missing_input_validation(node, code)
            self._check_model_extraction_risk(node, code)
            self._check_data_poisoning(node, code)
            self._check_adversarial_robustness(node, code)
    
    def _check_prompt_injection(self, node: ast.AST, code: str):
        """
        CWE-1295: Prompt Injection
        Detect unvalidated user input in LLM prompts
        """
        if isinstance(node, ast.Call):
            # Check for LLM API calls
            func_name = self._get_full_func_name(node.func)
            
            if any(api in func_name for api in self.LLM_APIS):
                # Check if user input is directly concatenated
                for keyword in node.keywords:
                    if keyword.arg in ['prompt', 'messages', 'input', 'text']:
                        value = keyword.value
                        
                        # Check for string concatenation with user input
                        if self._contains_user_input(value):
                            vuln = AIMLVulnerability(
                                cwe='CWE-1295',
                                title='Prompt Injection Vulnerability',
                                description=(
                                    'User input is directly concatenated into LLM prompt without validation. '
                                    'This allows attackers to inject malicious instructions, bypass system prompts, '
                                    'and manipulate model behavior.'
                                ),
                                severity='CRITICAL',
                                line=node.lineno,
                                column=node.col_offset,
                                code=self._extract_code_snippet(code, node.lineno),
                                fix=(
                                    'Use prompt templates with input sanitization:\n'
                                    'from langchain.prompts import PromptTemplate\n'
                                    'template = PromptTemplate.from_template("Answer: {user_input}")\n'
                                    'prompt = template.format(user_input=sanitize_input(user_input))'
                                ),
                                confidence=0.9
                            )
                            self.vulnerabilities.append(vuln)
    
    def _check_model_poisoning(self, node: ast.AST, code: str):
        """
        CWE-494: Model Poisoning via Untrusted Source
        Detect loading models from untrusted sources
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            
            # Check for model loading from untrusted sources
            if any(unsafe in func_name for unsafe in self.UNSAFE_MODEL_LOAD):
                # Check if source is a variable or URL
                if node.args:
                    source = node.args[0]
                    
                    # Flag if loading from URL or user input
                    is_url = False
                    is_user_input = False
                    
                    if isinstance(source, ast.Constant):
                        source_value = source.value
                        if isinstance(source_value, str):
                            if source_value.startswith(('http://', 'https://', 'ftp://')):
                                is_url = True
                    elif isinstance(source, (ast.Name, ast.Call)):
                        is_user_input = True
                    
                    if is_url or is_user_input:
                        vuln = AIMLVulnerability(
                            cwe='CWE-494',
                            title='Model Poisoning via Untrusted Source',
                            description=(
                                f'Model loaded using {func_name} from untrusted source. '
                                'Attackers can inject backdoors, bias the model, or extract training data. '
                                'Models from untrusted sources may contain trojans or privacy leaks.'
                            ),
                            severity='CRITICAL',
                            line=node.lineno,
                            column=node.col_offset,
                            code=self._extract_code_snippet(code, node.lineno),
                            fix=(
                                'Use safe model loading with integrity checks:\n'
                                '1. Verify model signatures/checksums\n'
                                '2. Load from trusted sources only\n'
                                '3. Use safetensors format instead of pickle\n'
                                'Example:\n'
                                'from safetensors.torch import load_model\n'
                                'model = load_model(model, "model.safetensors")'
                            ),
                            confidence=0.95
                        )
                        self.vulnerabilities.append(vuln)
    
    def _check_insecure_model_load(self, node: ast.AST, code: str):
        """
        CWE-502: Deserialization of Untrusted Data (ML Models)
        Detect unsafe model deserialization
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            
            # Specifically flag pickle.load and torch.load without weights_only
            if 'pickle.load' in func_name:
                vuln = AIMLVulnerability(
                    cwe='CWE-502',
                    title='Insecure Model Deserialization (pickle)',
                    description=(
                        'pickle.load() can execute arbitrary code during deserialization. '
                        'Malicious models can compromise the system upon loading. '
                        'This is especially dangerous for user-uploaded models.'
                    ),
                    severity='CRITICAL',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Use safe alternatives:\n'
                        '1. For PyTorch: torch.load(path, weights_only=True)\n'
                        '2. For general models: Use safetensors format\n'
                        '3. For scikit-learn: Use skops for safe loading\n'
                        'Example:\n'
                        'import torch\n'
                        'model.load_state_dict(torch.load("model.pth", weights_only=True))'
                    ),
                    confidence=1.0
                )
                self.vulnerabilities.append(vuln)
            
            elif 'torch.load' in func_name:
                # Check if weights_only parameter is used
                has_weights_only = False
                for keyword in node.keywords:
                    if keyword.arg == 'weights_only':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value:
                            has_weights_only = True
                
                if not has_weights_only:
                    vuln = AIMLVulnerability(
                        cwe='CWE-502',
                        title='Insecure PyTorch Model Loading',
                        description=(
                            'torch.load() without weights_only=True can execute arbitrary code. '
                            'Always use weights_only=True when loading models from files.'
                        ),
                        severity='HIGH',
                        line=node.lineno,
                        column=node.col_offset,
                        code=self._extract_code_snippet(code, node.lineno),
                        fix=(
                            'Add weights_only=True parameter:\n'
                            'model.load_state_dict(torch.load("model.pth", weights_only=True))'
                        ),
                        confidence=0.95
                    )
                    self.vulnerabilities.append(vuln)
    
    def _check_missing_input_validation(self, node: ast.AST, code: str):
        """
        CWE-20: Missing Input Validation for ML Inference
        Detect inference without input validation
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            
            # Check for model inference calls
            inference_patterns = [
                'predict',
                'predict_proba',
                'forward',
                'generate',
                '__call__',
                'inference'
            ]
            
            if any(pattern in func_name for pattern in inference_patterns):
                # Check if there's input validation before this call
                # Look for common validation patterns in parent scope
                # This is a heuristic check
                
                vuln = AIMLVulnerability(
                    cwe='CWE-20',
                    title='Missing Input Validation for ML Inference',
                    description=(
                        'Model inference without input validation. '
                        'Adversarial inputs can manipulate model predictions, '
                        'cause crashes, or expose training data.'
                    ),
                    severity='MEDIUM',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Add input validation before inference:\n'
                        '1. Check data types and shapes\n'
                        '2. Validate value ranges\n'
                        '3. Sanitize text inputs\n'
                        '4. Apply input normalization\n'
                        'Example:\n'
                        'def validate_input(data):\n'
                        '    if not isinstance(data, np.ndarray):\n'
                        '        raise ValueError("Invalid input type")\n'
                        '    if data.shape != expected_shape:\n'
                        '        raise ValueError("Invalid input shape")\n'
                        '    return np.clip(data, min_val, max_val)'
                    ),
                    confidence=0.7
                )
                self.vulnerabilities.append(vuln)
    
    def _check_model_extraction_risk(self, node: ast.AST, code: str):
        """
        CWE-201: Model Extraction via Excessive Information Exposure
        Detect exposure of model internals or confidence scores
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            
            # Check for exposure of model probabilities or internal states
            if 'predict_proba' in func_name or 'softmax' in func_name:
                # Check if output is returned directly to user
                # This is a heuristic - look for return statements nearby
                
                vuln = AIMLVulnerability(
                    cwe='CWE-201',
                    title='Model Extraction Risk via Probability Exposure',
                    description=(
                        'Exposing raw prediction probabilities or confidence scores '
                        'enables model extraction attacks. Attackers can query the model '
                        'repeatedly to steal its functionality.'
                    ),
                    severity='MEDIUM',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Limit information exposure:\n'
                        '1. Return only top prediction, not probabilities\n'
                        '2. Round confidence scores to reduce precision\n'
                        '3. Implement rate limiting on inference API\n'
                        '4. Add noise to outputs (differential privacy)\n'
                        'Example:\n'
                        'def safe_predict(model, input):\n'
                        '    probs = model.predict_proba(input)\n'
                        '    top_class = np.argmax(probs)\n'
                        '    return {"prediction": top_class}  # Don\'t expose probs'
                    ),
                    confidence=0.65
                )
                self.vulnerabilities.append(vuln)
    
    def _check_data_poisoning(self, node: ast.AST, code: str):
        """
        CWE-829: Data Poisoning via Untrusted Training Data
        Detect training with untrusted data sources
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            
            # Check for model training calls
            training_patterns = ['fit', 'train', 'fine_tune', 'fit_transform']
            
            if any(pattern in func_name for pattern in training_patterns):
                # Check if data comes from user input or external sources
                for arg in node.args:
                    if self._is_external_data_source(arg):
                        vuln = AIMLVulnerability(
                            cwe='CWE-829',
                            title='Data Poisoning via Untrusted Training Data',
                            description=(
                                'Training model with untrusted or user-provided data. '
                                'Attackers can inject poisoned samples to bias model predictions, '
                                'create backdoors, or degrade model performance.'
                            ),
                            severity='HIGH',
                            line=node.lineno,
                            column=node.col_offset,
                            code=self._extract_code_snippet(code, node.lineno),
                            fix=(
                                'Implement data validation and sanitization:\n'
                                '1. Validate data provenance and integrity\n'
                                '2. Detect and filter outliers/anomalies\n'
                                '3. Use data sanitization techniques\n'
                                '4. Implement robust training (e.g., RONI, DPA)\n'
                                'Example:\n'
                                'from sklearn.ensemble import IsolationForest\n'
                                'clf = IsolationForest(contamination=0.1)\n'
                                'anomalies = clf.fit_predict(training_data)\n'
                                'clean_data = training_data[anomalies == 1]'
                            ),
                            confidence=0.8
                        )
                        self.vulnerabilities.append(vuln)
    
    def _check_adversarial_robustness(self, node: ast.AST, code: str):
        """
        CWE-693: Missing Defense Against Adversarial Examples
        Detect lack of adversarial robustness measures
        """
        # Check for inference without adversarial defenses
        if isinstance(node, ast.FunctionDef):
            # Look for inference functions without adversarial defenses
            func_body = ast.unparse(node) if hasattr(ast, 'unparse') else ''
            
            has_inference = any(pattern in func_body.lower() for pattern in ['predict', 'inference', 'forward'])
            has_defense = any(defense in func_body.lower() for defense in [
                'adversarial', 'robust', 'defense', 'clip', 'normalize', 'validate'
            ])
            
            if has_inference and not has_defense:
                vuln = AIMLVulnerability(
                    cwe='CWE-693',
                    title='Missing Adversarial Robustness',
                    description=(
                        'Model inference without adversarial defenses. '
                        'Adversarial examples can manipulate predictions with imperceptible perturbations. '
                        'This is critical for security-sensitive applications.'
                    ),
                    severity='MEDIUM',
                    line=node.lineno,
                    column=node.col_offset,
                    code=self._extract_code_snippet(code, node.lineno),
                    fix=(
                        'Implement adversarial defenses:\n'
                        '1. Input preprocessing (JPEG compression, bit depth reduction)\n'
                        '2. Adversarial training\n'
                        '3. Certified defenses (randomized smoothing)\n'
                        '4. Input validation and anomaly detection\n'
                        'Example:\n'
                        'from art.defences.preprocessor import JpegCompression\n'
                        'defense = JpegCompression(clip_values=(0, 255), quality=50)\n'
                        'defended_input = defense(input_data)'
                    ),
                    confidence=0.6
                )
                self.vulnerabilities.append(vuln)
    
    def _detect_js_aiml_vulns(self, code: str, filename: str):
        """Detect JavaScript/TypeScript AI/ML vulnerabilities"""
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for OpenAI API calls with string concatenation
            if 'openai.chat.completions.create' in line or 'openai.completions.create' in line:
                if '${' in line or '+' in line:
                    vuln = AIMLVulnerability(
                        cwe='CWE-1295',
                        title='Prompt Injection Vulnerability (JavaScript)',
                        description=(
                            'User input directly concatenated into LLM prompt. '
                            'Use template literals with sanitization.'
                        ),
                        severity='CRITICAL',
                        line=line_num,
                        column=0,
                        code=line.strip(),
                        fix=(
                            'Use prompt templates:\n'
                            'const prompt = sanitizeInput(userInput);\n'
                            'const response = await openai.chat.completions.create({\n'
                            '  messages: [{role: "user", content: prompt}]\n'
                            '});'
                        ),
                        confidence=0.85
                    )
                    self.vulnerabilities.append(vuln)
            
            # Check for TensorFlow.js model loading from URLs
            if 'tf.loadLayersModel' in line or 'tf.loadGraphModel' in line:
                if 'http://' in line or 'https://' in line:
                    vuln = AIMLVulnerability(
                        cwe='CWE-494',
                        title='Model Loading from Untrusted URL',
                        description='Loading ML model from external URL without verification.',
                        severity='HIGH',
                        line=line_num,
                        column=0,
                        code=line.strip(),
                        fix='Verify model checksums and load from trusted CDN only.',
                        confidence=0.9
                    )
                    self.vulnerabilities.append(vuln)
    
    def _detect_java_aiml_vulns(self, code: str, filename: str):
        """Detect Java AI/ML vulnerabilities"""
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for DL4J model deserialization
            if 'ModelSerializer.restoreMultiLayerNetwork' in line:
                if 'new File' in line or 'url' in line.lower():
                    vuln = AIMLVulnerability(
                        cwe='CWE-502',
                        title='Insecure Model Deserialization (Java)',
                        description='Loading DL4J model without integrity checks.',
                        severity='HIGH',
                        line=line_num,
                        column=0,
                        code=line.strip(),
                        fix='Verify model signatures before loading.',
                        confidence=0.85
                    )
                    self.vulnerabilities.append(vuln)
    
    # Helper methods
    
    def _get_full_func_name(self, func_node: ast.AST) -> str:
        """Get full function name from AST node"""
        if isinstance(func_node, ast.Attribute):
            return f'{self._get_full_func_name(func_node.value)}.{func_node.attr}'
        elif isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Call):
            return self._get_full_func_name(func_node.func)
        return ''
    
    def _contains_user_input(self, node: ast.AST) -> bool:
        """Check if AST node contains user input patterns"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # String concatenation
            return True
        elif isinstance(node, ast.JoinedStr):
            # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    return True
        elif isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            # Check for format(), input(), request.args, etc.
            if any(pattern in func_name for pattern in ['format', 'input', 'request', 'args', 'form']):
                return True
        return False
    
    def _is_external_data_source(self, node: ast.AST) -> bool:
        """Check if data comes from external source"""
        if isinstance(node, ast.Call):
            func_name = self._get_full_func_name(node.func)
            external_patterns = [
                'requests.get',
                'urlopen',
                'read_csv',
                'pd.read',
                'tf.data.Dataset',
                'datasets.load_dataset'
            ]
            return any(pattern in func_name for pattern in external_patterns)
        return False
    
    def _extract_code_snippet(self, code: str, line_num: int, context: int = 2) -> str:
        """Extract code snippet with context"""
        lines = code.split('\n')
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    
    def _detect_with_regex(self, code: str):
        """Fallback regex-based detection when AST parsing fails"""
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Prompt injection
            if any(api in line for api in ['openai', 'anthropic', 'cohere']) and ('+' in line or 'format(' in line):
                vuln = AIMLVulnerability(
                    cwe='CWE-1295',
                    title='Potential Prompt Injection',
                    description='User input may be concatenated into LLM prompt.',
                    severity='HIGH',
                    line=line_num,
                    column=0,
                    code=line.strip(),
                    fix='Use prompt templates with input validation.',
                    confidence=0.7
                )
                self.vulnerabilities.append(vuln)
            
            # Unsafe model loading
            if 'pickle.load' in line or ('torch.load' in line and 'weights_only' not in line):
                vuln = AIMLVulnerability(
                    cwe='CWE-502',
                    title='Insecure Model Deserialization',
                    description='Unsafe model loading detected.',
                    severity='CRITICAL',
                    line=line_num,
                    column=0,
                    code=line.strip(),
                    fix='Use safe loading methods with integrity checks.',
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)


# Example usage
if __name__ == '__main__':
    detector = AIMLSecurityDetector()
    
    # Test case 1: Prompt injection
    test_code_1 = """
import openai

def chat_with_user(user_input):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Answer: " + user_input}]
    )
    return response
"""
    
    vulns = detector.detect_all(test_code_1, 'python')
    print(f"Found {len(vulns)} vulnerabilities in test case 1")
    for v in vulns:
        print(f"  [{v.cwe}] {v.title} at line {v.line}")
    
    # Test case 2: Insecure model loading
    test_code_2 = """
import torch
import pickle

def load_model(model_path):
    model = pickle.load(open(model_path, 'rb'))
    return model

def load_torch_model(path):
    model = torch.load(path)  # Missing weights_only=True
    return model
"""
    
    vulns = detector.detect_all(test_code_2, 'python')
    print(f"\nFound {len(vulns)} vulnerabilities in test case 2")
    for v in vulns:
        print(f"  [{v.cwe}] {v.title} at line {v.line}")
