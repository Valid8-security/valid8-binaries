"""
ML-Based False Positive Reduction

This module uses machine learning to reduce false positives by learning from:
1. Historical scan data
2. User feedback (validated/dismissed vulnerabilities)  
3. Code context and patterns
4. Confidence scores from multiple detection techniques

The ML model predicts whether a detected vulnerability is a true positive or false positive.
Target: Reduce false positives from 12% to <8%
"""

import json
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import hashlib

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import precision_score, recall_score, f1_score
    HAS_ML = True
except ImportError:
    HAS_ML = False
    np = None
    RandomForestClassifier = None


@dataclass
class VulnerabilityFeatures:
    """Features extracted from a vulnerability for ML classification"""
    cwe: str
    severity: str
    confidence: float
    line_number: int
    file_extension: str
    context_length: int
    has_sanitization: bool
    has_validation: bool
    pattern_match_count: int
    ai_detected: bool
    in_test_file: bool
    in_generated_file: bool
    code_complexity: int  # Lines of code in function/method
    detection_technique_count: int  # How many techniques detected this
    cross_validated: bool  # Did multiple techniques agree
    
    def to_vector(self) -> List[float]:
        """Convert features to numeric vector for ML"""
        return [
            self._encode_cwe(self.cwe),
            self._encode_severity(self.severity),
            self.confidence,
            min(self.line_number / 1000.0, 1.0),  # Normalize line number
            self._encode_extension(self.file_extension),
            min(self.context_length / 100.0, 1.0),  # Normalize context length
            float(self.has_sanitization),
            float(self.has_validation),
            min(self.pattern_match_count / 5.0, 1.0),  # Normalize match count
            float(self.ai_detected),
            float(self.in_test_file),
            float(self.in_generated_file),
            min(self.code_complexity / 100.0, 1.0),  # Normalize complexity
            min(self.detection_technique_count / 3.0, 1.0),  # Normalize technique count
            float(self.cross_validated),
        ]
    
    @staticmethod
    def _encode_cwe(cwe: str) -> float:
        """Encode CWE as numeric value based on severity"""
        # High-risk CWEs get higher values
        high_risk = ['89', '79', '78', '22', '94', '502', '611']  # SQL injection, XSS, Command injection, etc.
        medium_risk = ['200', '209', '330', '331', '338', '759']  # Info disclosure, weak crypto
        
        if any(c in cwe for c in high_risk):
            return 0.9
        elif any(c in cwe for c in medium_risk):
            return 0.5
        return 0.3
    
    @staticmethod
    def _encode_severity(severity: str) -> float:
        """Encode severity as numeric value"""
        severity_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        return severity_map.get(severity.lower(), 0.5)
    
    @staticmethod
    def _encode_extension(ext: str) -> float:
        """Encode file extension (some languages have higher false positive rates)"""
        # Languages with strong type systems tend to have fewer false positives
        low_fp = ['.ts', '.rs', '.go', '.java']
        high_fp = ['.js', '.php', '.rb']
        
        if ext in low_fp:
            return 0.3
        elif ext in high_fp:
            return 0.7
        return 0.5


class MLFalsePositiveReducer:
    """ML-based false positive reduction using Random Forest"""
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize the ML false positive reducer
        
        Args:
            model_path: Path to saved model. If None, uses default location.
        """
        if not HAS_ML:
            raise ImportError("sklearn and numpy are required for ML false positive reduction")
        
        self.model_path = model_path or Path.home() / '.parry' / 'ml_model.pkl'
        self.training_data_path = Path.home() / '.parry' / 'training_data.jsonl'
        self.model = None
        self.feature_importance = None
        
        # Load existing model if available
        if self.model_path.exists():
            self.load_model()
        else:
            # Initialize new model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'  # Handle imbalanced data
            )
    
    def extract_features(self, vuln: Dict[str, Any], code: str, filepath: str) -> VulnerabilityFeatures:
        """
        Extract features from a vulnerability for ML classification
        
        Args:
            vuln: Vulnerability dict with keys like cwe, severity, confidence, line
            code: Source code context
            filepath: Path to file
            
        Returns:
            VulnerabilityFeatures object
        """
        # Extract basic features
        cwe = vuln.get('cwe', 'CWE-unknown')
        severity = vuln.get('severity', 'medium')
        confidence = vuln.get('confidence', 0.5)
        line_number = vuln.get('line', 0)
        file_extension = Path(filepath).suffix
        
        # Extract code context features
        lines = code.split('\n')
        line_idx = max(0, line_number - 1)
        
        # Get context window (10 lines before and after)
        context_start = max(0, line_idx - 10)
        context_end = min(len(lines), line_idx + 10)
        context = '\n'.join(lines[context_start:context_end])
        context_length = len(context)
        
        # Check for sanitization/validation patterns
        has_sanitization = self._has_sanitization(context)
        has_validation = self._has_validation(context)
        
        # Check if in test or generated file
        in_test_file = self._is_test_file(filepath)
        in_generated_file = self._is_generated_file(filepath, code)
        
        # Calculate code complexity (simple heuristic: lines in current function)
        code_complexity = self._calculate_complexity(lines, line_idx)
        
        # Detection metadata
        pattern_match_count = vuln.get('pattern_match_count', 1)
        ai_detected = vuln.get('ai_detected', False)
        detection_technique_count = vuln.get('detection_technique_count', 1)
        cross_validated = vuln.get('cross_validated', False)
        
        return VulnerabilityFeatures(
            cwe=cwe,
            severity=severity,
            confidence=confidence,
            line_number=line_number,
            file_extension=file_extension,
            context_length=context_length,
            has_sanitization=has_sanitization,
            has_validation=has_validation,
            pattern_match_count=pattern_match_count,
            ai_detected=ai_detected,
            in_test_file=in_test_file,
            in_generated_file=in_generated_file,
            code_complexity=code_complexity,
            detection_technique_count=detection_technique_count,
            cross_validated=cross_validated
        )
    
    def _has_sanitization(self, context: str) -> bool:
        """Check if context contains sanitization patterns"""
        sanitization_patterns = [
            'sanitize', 'escape', 'encode', 'filter', 'clean',
            'validate', 'strip_tags', 'htmlspecialchars', 'parameterized',
            'prepared_statement', 'bind_param', 'placeholder'
        ]
        context_lower = context.lower()
        return any(pattern in context_lower for pattern in sanitization_patterns)
    
    def _has_validation(self, context: str) -> bool:
        """Check if context contains validation patterns"""
        validation_patterns = [
            'if not', 'assert', 'raise', 'throw', 'check',
            'is_valid', 'validate', 'verify', 'isinstance',
            'in whitelist', 'allowed_'
        ]
        context_lower = context.lower()
        return any(pattern in context_lower for pattern in validation_patterns)
    
    def _is_test_file(self, filepath: str) -> bool:
        """Check if file is a test file (higher false positive rate)"""
        test_indicators = ['test_', '_test', '/test/', '/tests/', 'spec.', '.spec', '__test__']
        filepath_lower = filepath.lower()
        return any(indicator in filepath_lower for indicator in test_indicators)
    
    def _is_generated_file(self, filepath: str, code: str) -> bool:
        """Check if file is auto-generated (should be ignored)"""
        # Check filename
        if 'generated' in filepath.lower() or '.generated.' in filepath.lower():
            return True
        
        # Check for generation markers in code (first 500 chars)
        header = code[:500].lower()
        generation_markers = [
            'auto-generated', 'autogenerated', 'do not edit',
            'generated by', 'automatically generated'
        ]
        return any(marker in header for marker in generation_markers)
    
    def _calculate_complexity(self, lines: List[str], line_idx: int) -> int:
        """Calculate code complexity (simple heuristic based on function size)"""
        # Find function boundaries
        indent_level = len(lines[line_idx]) - len(lines[line_idx].lstrip())
        
        # Count lines with same or greater indentation (part of same function)
        complexity = 1
        for i in range(line_idx, min(len(lines), line_idx + 100)):
            if i == line_idx:
                continue
            line = lines[i]
            if line.strip():
                line_indent = len(line) - len(line.lstrip())
                if line_indent >= indent_level:
                    complexity += 1
                elif line_indent < indent_level:
                    break
        
        return complexity
    
    def predict_false_positive(self, vuln: Dict[str, Any], code: str, filepath: str) -> Tuple[bool, float]:
        """
        Predict if vulnerability is a false positive
        
        Args:
            vuln: Vulnerability dict
            code: Source code
            filepath: File path
            
        Returns:
            (is_false_positive: bool, confidence: float)
        """
        if self.model is None:
            # No model trained yet, use heuristics
            return self._heuristic_filter(vuln, code, filepath)
        
        # Extract features
        features = self.extract_features(vuln, code, filepath)
        feature_vector = np.array([features.to_vector()])
        
        # Predict
        prediction = self.model.predict(feature_vector)[0]
        probabilities = self.model.predict_proba(feature_vector)[0]
        
        # prediction = 1 means true positive, 0 means false positive
        is_false_positive = (prediction == 0)
        confidence = probabilities[prediction]
        
        return is_false_positive, confidence
    
    def _heuristic_filter(self, vuln: Dict[str, Any], code: str, filepath: str) -> Tuple[bool, float]:
        """Fallback heuristic-based filtering when no model is available"""
        features = self.extract_features(vuln, code, filepath)
        
        # Simple heuristic rules
        false_positive_score = 0.0
        
        # High confidence from multiple techniques → likely true positive
        if features.cross_validated and features.confidence > 0.8:
            false_positive_score -= 0.3
        
        # In test file with low severity → likely false positive
        if features.in_test_file and features.severity in ['low', 'info']:
            false_positive_score += 0.4
        
        # Has sanitization or validation → might be false positive
        if features.has_sanitization or features.has_validation:
            false_positive_score += 0.2
        
        # In generated file → definitely false positive
        if features.in_generated_file:
            false_positive_score += 0.9
        
        # Low confidence → likely false positive
        if features.confidence < 0.4:
            false_positive_score += 0.3
        
        is_false_positive = false_positive_score > 0.5
        confidence = abs(false_positive_score - 0.5) * 2  # Normalize to 0-1
        
        return is_false_positive, confidence
    
    def train(self, training_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Train the ML model on labeled data
        
        Args:
            training_data: List of dicts with keys:
                - vuln: Vulnerability dict
                - code: Source code
                - filepath: File path
                - is_true_positive: bool (label)
                
        Returns:
            Training metrics (precision, recall, f1)
        """
        if not HAS_ML:
            raise ImportError("sklearn required for training")
        
        if len(training_data) < 10:
            raise ValueError("Need at least 10 training samples")
        
        # Extract features and labels
        X = []
        y = []
        
        for sample in training_data:
            vuln = sample['vuln']
            code = sample['code']
            filepath = sample['filepath']
            is_true_positive = sample['is_true_positive']
            
            features = self.extract_features(vuln, code, filepath)
            X.append(features.to_vector())
            y.append(1 if is_true_positive else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'training_samples': len(training_data)
        }
        
        # Store feature importance
        self.feature_importance = self.model.feature_importances_
        
        # Save model
        self.save_model()
        
        return metrics
    
    def add_feedback(self, vuln: Dict[str, Any], code: str, filepath: str, is_true_positive: bool):
        """
        Add user feedback to training data
        
        Args:
            vuln: Vulnerability dict
            code: Source code
            filepath: File path
            is_true_positive: Whether user confirmed this as true positive
        """
        # Append to training data file
        training_sample = {
            'vuln': vuln,
            'code': code,
            'filepath': filepath,
            'is_true_positive': is_true_positive,
            'timestamp': str(Path.cwd())  # Placeholder timestamp
        }
        
        # Ensure directory exists
        self.training_data_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Append to JSONL file
        with open(self.training_data_path, 'a') as f:
            f.write(json.dumps(training_sample) + '\n')
    
    def load_training_data(self) -> List[Dict[str, Any]]:
        """Load training data from file"""
        if not self.training_data_path.exists():
            return []
        
        training_data = []
        with open(self.training_data_path, 'r') as f:
            for line in f:
                if line.strip():
                    training_data.append(json.loads(line))
        
        return training_data
    
    def retrain_from_feedback(self) -> Optional[Dict[str, float]]:
        """Retrain model using accumulated feedback data"""
        training_data = self.load_training_data()
        
        if len(training_data) < 10:
            print(f"Not enough training data ({len(training_data)} samples). Need at least 10.")
            return None
        
        print(f"Retraining model with {len(training_data)} samples...")
        metrics = self.train(training_data)
        print(f"Training complete. Metrics: {metrics}")
        
        return metrics
    
    def save_model(self):
        """Save trained model to disk"""
        if self.model is None:
            return
        
        # Ensure directory exists
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_data = {
            'model': self.model,
            'feature_importance': self.feature_importance
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self):
        """Load trained model from disk"""
        if not self.model_path.exists():
            return
        
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.feature_importance = model_data.get('feature_importance')
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
    
    def filter_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        code_files: Dict[str, str],
        confidence_threshold: float = 0.7
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter vulnerabilities to remove false positives
        
        Args:
            vulnerabilities: List of vulnerability dicts
            code_files: Dict mapping filepath to code content
            confidence_threshold: Minimum confidence to suppress false positive
            
        Returns:
            (true_positives, false_positives) tuple of lists
        """
        true_positives = []
        false_positives = []
        
        for vuln in vulnerabilities:
            filepath = vuln.get('file', '')
            code = code_files.get(filepath, '')
            
            is_fp, confidence = self.predict_false_positive(vuln, code, filepath)
            
            if is_fp and confidence >= confidence_threshold:
                # High confidence it's a false positive → filter out
                vuln['filtered_reason'] = f'ML model predicted false positive (confidence: {confidence:.2%})'
                false_positives.append(vuln)
            else:
                # Keep as true positive
                if confidence < confidence_threshold:
                    vuln['fp_risk'] = 'low'
                else:
                    vuln['fp_risk'] = 'unknown'
                true_positives.append(vuln)
        
        return true_positives, false_positives
    
    def get_feature_importance_report(self) -> str:
        """Generate a report of feature importance"""
        if self.feature_importance is None:
            return "Model not trained yet"
        
        feature_names = [
            'CWE encoding',
            'Severity',
            'Confidence',
            'Line number (normalized)',
            'File extension',
            'Context length',
            'Has sanitization',
            'Has validation',
            'Pattern match count',
            'AI detected',
            'In test file',
            'In generated file',
            'Code complexity',
            'Detection technique count',
            'Cross-validated'
        ]
        
        # Sort by importance
        importance_pairs = sorted(
            zip(feature_names, self.feature_importance),
            key=lambda x: x[1],
            reverse=True
        )
        
        report = "Feature Importance Report\n"
        report += "=" * 50 + "\n\n"
        
        for feature, importance in importance_pairs:
            bar = '█' * int(importance * 50)
            report += f"{feature:30s} {bar} {importance:.3f}\n"
        
        return report


def create_training_samples_from_benchmark() -> List[Dict[str, Any]]:
    """Create initial training samples from benchmark results (if available)"""
    training_samples = []
    
    # This would load ground truth from benchmarking
    # For now, return empty list - user will add feedback over time
    
    return training_samples


def reduce_false_positives(
    scan_results: Dict[str, Any],
    confidence_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Main entry point for ML-based false positive reduction
    
    Args:
        scan_results: Scan results dict with 'vulnerabilities' key
        confidence_threshold: Confidence threshold for filtering
        
    Returns:
        Modified scan results with false positives filtered
    """
    if not HAS_ML:
        print("Warning: sklearn not available. Skipping ML false positive reduction.")
        return scan_results
    
    # Initialize reducer
    reducer = MLFalsePositiveReducer()
    
    # Extract vulnerabilities and code
    vulnerabilities = scan_results.get('vulnerabilities', [])
    code_files = {}  # Would be populated from file system
    
    # For now, skip filtering if we don't have trained model
    if reducer.model is None:
        print("ML model not trained yet. Use pattern-based filtering only.")
        return scan_results
    
    # Filter vulnerabilities
    true_positives, false_positives = reducer.filter_vulnerabilities(
        vulnerabilities,
        code_files,
        confidence_threshold
    )
    
    # Update scan results
    scan_results['vulnerabilities'] = true_positives
    scan_results['false_positives_filtered'] = len(false_positives)
    scan_results['filtered_vulnerabilities'] = false_positives
    
    return scan_results
