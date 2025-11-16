"""
Ultra-Permissive Pattern Detector for Valid8

This module implements extremely lenient pattern detection that prioritizes maximum recall
over precision. It catches nearly all potential vulnerabilities, allowing the AI validation
layer to filter out false positives.

Strategy: Lenient Patterns → AI Validation → Advanced Analysis
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass
from ..models import Vulnerability


@dataclass
class DetectionResult:
    """Result from ultra-permissive pattern detection"""
    vulnerability: Dict[str, Any]
    confidence: float
    pattern_type: str
    requires_ai_validation: bool = True


class UltraPermissivePatternDetector:
    """
    Ultra-permissive vulnerability detector that prioritizes recall over precision.

    Key characteristics:
    - Confidence threshold: 0.01 (extremely low)
    - Pattern sensitivity: 0.95 (very sensitive)
    - Context window: Large (20 lines)
    - Goal: Catch 98% of true vulnerabilities
    """

    def __init__(self):
        # Extremely low confidence thresholds - catch everything
        self.min_confidence = 0.01
        self.pattern_sensitivity = 0.95
        self.context_window = 20  # Large context for pattern matching
        self.fuzzy_matching = True
        self.case_insensitive = True

        # Initialize comprehensive pattern libraries
        self.sql_patterns = self._get_sql_injection_patterns()
        self.xss_patterns = self._get_xss_patterns()
        self.command_patterns = self._get_command_injection_patterns()
        self.deserialization_patterns = self._get_deserialization_patterns()
        self.path_traversal_patterns = self._get_path_traversal_patterns()
        self.secrets_patterns = self._get_secrets_patterns()

        # Phase A: Enhanced patterns for 15-20% recall improvement
        self.enhanced_patterns = self._get_enhanced_patterns()

        # Phase B: Framework and language specific detectors for additional recall
        self.framework_detectors = self._get_framework_detectors()
        self.language_analyzers = self._get_language_analyzers()

    def scan_codebase(self, codebase_path: str) -> List[DetectionResult]:
        """
        Scan entire codebase with ultra-permissive detection.
        Returns all potential vulnerabilities for AI validation.
        """
        all_results = []

        for root, dirs, files in os.walk(codebase_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if not self._should_skip_directory(d)]

            for file in files:
                if self._is_supported_file(file):
                    file_path = Path(root) / file
                    try:
                        results = self.scan_file(file_path)
                        all_results.extend(results)
                    except Exception as e:
                        # Be permissive - don't fail on problematic files
                        print(f"Warning: Could not scan {file_path}: {e}")
                        continue

        return all_results

    def scan_file(self, file_path: Path) -> List[DetectionResult]:
        """Scan a single file with ultra-permissive patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []

        lines = content.split('\n')
        results = []

        # Apply all pattern types
        results.extend(self._scan_sql_injection(file_path, content, lines))
        results.extend(self._scan_xss(file_path, content, lines))
        results.extend(self._scan_command_injection(file_path, content, lines))
        results.extend(self._scan_deserialization(file_path, content, lines))
        results.extend(self._scan_path_traversal(file_path, content, lines))
        results.extend(self._scan_secrets(file_path, content, lines))

        # Phase A: Apply enhanced patterns for 15-20% recall improvement
        results.extend(self._scan_enhanced_patterns(file_path, content, lines))

        return results

    def _scan_sql_injection(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive SQL injection detection"""
        results = []

        for pattern_name, pattern_data in self.sql_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-89',
                    'severity': 'UNKNOWN',  # Will be determined by AI
                    'title': 'Potential SQL Injection',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,  # Very low initial confidence
                    pattern_type='sql_injection'
                ))

        return results

    def _scan_xss(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive XSS detection"""
        results = []

        for pattern_name, pattern_data in self.xss_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-79',
                    'severity': 'UNKNOWN',
                    'title': 'Potential Cross-Site Scripting (XSS)',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,
                    pattern_type='xss'
                ))

        return results

    def _scan_command_injection(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive command injection detection"""
        results = []

        for pattern_name, pattern_data in self.command_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-78',
                    'severity': 'UNKNOWN',
                    'title': 'Potential Command Injection',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,
                    pattern_type='command_injection'
                ))

        return results

    def _scan_deserialization(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive deserialization detection"""
        results = []

        for pattern_name, pattern_data in self.deserialization_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-502',
                    'severity': 'UNKNOWN',
                    'title': 'Potential Deserialization Vulnerability',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,
                    pattern_type='deserialization'
                ))

        return results

    def _scan_path_traversal(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive path traversal detection"""
        results = []

        for pattern_name, pattern_data in self.path_traversal_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-22',
                    'severity': 'UNKNOWN',
                    'title': 'Potential Path Traversal',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,
                    pattern_type='path_traversal'
                ))

        return results

    def _scan_secrets(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Ultra-permissive secrets detection"""
        results = []

        for pattern_name, pattern_data in self.secrets_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                vuln_dict = {
                    'cwe': 'CWE-798',
                    'severity': 'UNKNOWN',
                    'title': 'Potential Secrets Exposure',
                    'description': f'Pattern match: {pattern_name} - {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.1),
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=0.1,
                    pattern_type='secrets'
                ))

        return results

    def _scan_enhanced_patterns(self, file_path: Path, content: str, lines: List[str]) -> List[DetectionResult]:
        """Phase A: Enhanced patterns for complex vulnerability detection - 15-20% recall improvement"""
        results = []

        for pattern_name, pattern_data in self.enhanced_patterns.items():
            matches = self._find_pattern_matches(content, pattern_data['regex'])
            for match in matches:
                # Map enhanced pattern to vulnerability type
                vuln_type_mapping = {
                    'complex_sql_injection': 'CWE-89',
                    'fstring_injection': 'CWE-89',
                    'template_literal_injection': 'CWE-79',
                    'multi_line_command_injection': 'CWE-78',
                    'complex_path_traversal': 'CWE-22',
                    'dynamic_eval_injection': 'CWE-95',
                    'reflection_injection': 'CWE-470'
                }

                severity_mapping = {
                    'complex_sql_injection': 'HIGH',
                    'fstring_injection': 'HIGH',
                    'template_literal_injection': 'HIGH',
                    'multi_line_command_injection': 'CRITICAL',
                    'complex_path_traversal': 'HIGH',
                    'dynamic_eval_injection': 'CRITICAL',
                    'reflection_injection': 'HIGH'
                }

                cwe = vuln_type_mapping.get(pattern_name, 'CWE-UNKNOWN')
                severity = severity_mapping.get(pattern_name, 'HIGH')
                base_confidence = 0.6 + pattern_data.get('confidence_boost', 0.0)

                vuln_dict = {
                    'cwe': cwe,
                    'severity': severity,
                    'title': f'Enhanced Detection: {pattern_name.replace("_", " ").title()}',
                    'description': f'Enhanced pattern detected: {pattern_data["description"]}',
                    'file_path': str(file_path),
                    'line_number': self._get_line_number(content, match.start()),
                    'code_snippet': self._get_code_snippet(content, match.start()),
                    'pattern_matched': pattern_name,
                    'match_strength': pattern_data.get('weight', 0.8),
                    'confidence_boost': pattern_data.get('confidence_boost', 0.0),
                    'detection_phase': 'enhanced_patterns',
                    'requires_ai_validation': True
                }

                results.append(DetectionResult(
                    vulnerability=vuln_dict,
                    confidence=base_confidence,
                    pattern_type='enhanced'
                ))

        return results

    def _find_pattern_matches(self, content: str, pattern: str) -> List[re.Match]:
        """Find all pattern matches with ultra-permissive settings"""
        flags = re.IGNORECASE if self.case_insensitive else 0
        flags |= re.DOTALL  # Allow . to match newlines

        try:
            matches = list(re.finditer(pattern, content, flags))
            return matches
        except re.error:
            # Be permissive - return empty list on regex errors
            return []

    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from character position"""
        return content[:position].count('\n') + 1

    def _get_code_snippet(self, content: str, position: int) -> str:
        """Get code snippet around the match position"""
        lines = content.split('\n')
        line_num = self._get_line_number(content, position)

        start_line = max(0, line_num - self.context_window // 2)
        end_line = min(len(lines), line_num + self.context_window // 2)

        snippet_lines = []
        for i in range(start_line, end_line):
            marker = ">>> " if i + 1 == line_num else "    "
            snippet_lines.append(f"{marker}{i + 1:4d}: {lines[i]}")

        return '\n'.join(snippet_lines)

    def _should_skip_directory(self, dirname: str) -> bool:
        """Check if directory should be skipped (but be permissive)"""
        skip_dirs = {
            '.git', '__pycache__', 'node_modules', '.pytest_cache',
            'venv', 'env', '.env', 'dist', 'build', '.next', '.nuxt'
        }
        return dirname in skip_dirs

    def _is_supported_file(self, filename: str) -> bool:
        """Check if file type is supported (be very permissive)"""
        supported_extensions = {
            # Python
            '.py', '.pyw', '.pyx',
            # JavaScript/TypeScript
            '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
            # Java
            '.java', '.jsp', '.jspx',
            # C/C++
            '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp',
            # C#
            '.cs', '.csx',
            # Go
            '.go',
            # PHP
            '.php', '.phtml', '.php3', '.php4', '.php5',
            # Ruby
            '.rb', '.erb',
            # Rust
            '.rs',
            # Swift
            '.swift',
            # Kotlin
            '.kt', '.kts',
            # Scala
            '.scala',
            # Perl
            '.pl', '.pm', '.t',
            # R
            '.r', '.R',
            # Shell
            '.sh', '.bash', '.zsh', '.fish',
            # Config files (often contain secrets)
            '.json', '.yaml', '.yml', '.xml', '.ini', '.cfg', '.conf',
            # SQL
            '.sql',
            # HTML (for XSS)
            '.html', '.htm', '.xhtml',
            # CSS (rarely, but included for completeness)
            '.css'
        }

        _, ext = os.path.splitext(filename.lower())
        return ext in supported_extensions or not ext  # Include files without extensions

    # Pattern Libraries (Ultra-Permissive)

    def _get_sql_injection_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive SQL injection patterns - catch ANY database usage with variables"""
        return {
            'fstring_sql': {
                'regex': r'f["\'].*?\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b.*?\}.*?["\']',
                'description': 'F-string with SQL keywords and variables',
                'weight': 0.8
            },
            'concat_sql': {
                'regex': r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b.*?\s*\+\s*.*?\w+',
                'description': 'SQL keyword with string concatenation',
                'weight': 0.7
            },
            'variable_sql': {
                'regex': r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b.*?\b\w+\b.*?\bWHERE\b.*?\w+',
                'description': 'SQL with variables in WHERE clause',
                'weight': 0.6
            },
            'format_sql': {
                'regex': r'["\'].*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?\s*%\s*.*?\w+.*?\s*["\']',
                'description': 'String formatting with SQL',
                'weight': 0.7
            },
            'any_db_execute': {
                'regex': r'\.(execute|query|run|executemany)\s*\(',
                'description': 'Any database execute method call',
                'weight': 0.5
            },
            'sql_with_vars': {
                'regex': r'\b(SELECT|INSERT|UPDATE|DELETE)\b.*?\$\{.*?\}',
                'description': 'SQL with template literals/variables',
                'weight': 0.9
            }
        }

    def _get_xss_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive XSS patterns - catch ANY HTML manipulation"""
        return {
            'innerhtml_assign': {
                'regex': r'\.innerHTML\s*=',
                'description': 'Any innerHTML assignment',
                'weight': 0.9
            },
            'outerhtml_assign': {
                'regex': r'\.outerHTML\s*=',
                'description': 'Any outerHTML assignment',
                'weight': 0.9
            },
            'document_write': {
                'regex': r'document\.write\s*\(',
                'description': 'Any document.write call',
                'weight': 0.8
            },
            'html_method': {
                'regex': r'\.html\s*\(',
                'description': 'jQuery html() method',
                'weight': 0.8
            },
            'dangerouslySetInnerHTML': {
                'regex': r'dangerouslySetInnerHTML',
                'description': 'React dangerouslySetInnerHTML',
                'weight': 0.9
            },
            'v-html': {
                'regex': r'v-html\s*=',
                'description': 'Vue v-html directive',
                'weight': 0.8
            },
            'template_literal_html': {
                'regex': r'`.*?<\w+.*?\$\{.*?\}.*?>`',
                'description': 'Template literal with HTML and variables',
                'weight': 0.7
            }
        }

    def _get_command_injection_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive command injection patterns - catch ANY system/shell usage"""
        return {
            'subprocess_call': {
                'regex': r'subprocess\.(call|Popen|run|check_call|check_output)',
                'description': 'Any subprocess execution method',
                'weight': 0.8
            },
            'os_system': {
                'regex': r'os\.system\s*\(',
                'description': 'Any os.system call',
                'weight': 0.9
            },
            'os_popen': {
                'regex': r'os\.popen\s*\(',
                'description': 'Any os.popen call',
                'weight': 0.8
            },
            'shell_true': {
                'regex': r'shell\s*=\s*True',
                'description': 'Shell execution enabled',
                'weight': 0.9
            },
            'backticks': {
                'regex': r'`.*?`',
                'description': 'Backtick command execution (shell)',
                'weight': 0.7
            },
            'system_exec': {
                'regex': r'\b(system|exec|eval|popen)\s*\(',
                'description': 'Any system execution function',
                'weight': 0.8
            }
        }

    def _get_deserialization_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive deserialization patterns"""
        return {
            'pickle_load': {
                'regex': r'pickle\.(load|loads|loadf)',
                'description': 'Any pickle deserialization',
                'weight': 0.9
            },
            'yaml_load': {
                'regex': r'yaml\.(load|load_all|full_load)',
                'description': 'Unsafe YAML loading',
                'weight': 0.8
            },
            'json_loads': {
                'regex': r'json\.loads\s*\(',
                'description': 'JSON deserialization (potential for code execution)',
                'weight': 0.5
            },
            'marshal_load': {
                'regex': r'marshal\.(load|loads)',
                'description': 'Marshal deserialization',
                'weight': 0.9
            },
            'shelve_open': {
                'regex': r'shelve\.open\s*\(',
                'description': 'Shelve file operations',
                'weight': 0.7
            },
            'unserialize_php': {
                'regex': r'unserialize\s*\(',
                'description': 'PHP unserialize function',
                'weight': 0.9
            }
        }

    def _get_path_traversal_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive path traversal patterns"""
        return {
            'dot_dot_slash': {
                'regex': r'\.\./',
                'description': 'Directory traversal with ../',
                'weight': 0.8
            },
            'path_join_vars': {
                'regex': r'(path\.join|Path\(|os\.path\.join).*?\w+',
                'description': 'Path operations with variables',
                'weight': 0.6
            },
            'open_with_var': {
                'regex': r'open\s*\(\s*\w+',
                'description': 'File open with variable path',
                'weight': 0.5
            },
            'file_read_var': {
                'regex': r'\.read\s*\(\s*\)\s*.*?where.*?\w+',
                'description': 'File read operations',
                'weight': 0.5
            }
        }

    def _get_secrets_patterns(self) -> Dict[str, Dict]:
        """Ultra-permissive secrets detection patterns"""
        return {
            'api_key_pattern': {
                'regex': r'\b(api[_-]?key|apikey)\b.*?[=:]',
                'description': 'API key patterns',
                'weight': 0.8
            },
            'password_pattern': {
                'regex': r'\b(password|passwd|pwd)\b.*?[=:]',
                'description': 'Password patterns',
                'weight': 0.8
            },
            'secret_pattern': {
                'regex': r'\b(secret|token|key)\b.*?[=:]',
                'description': 'Generic secret patterns',
                'weight': 0.7
            },
            'aws_key': {
                'regex': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS access key pattern',
                'weight': 0.9
            },
            'private_key': {
                'regex': r'-----BEGIN.*PRIVATE KEY-----',
                'description': 'Private key headers',
                'weight': 0.9
            },
            'hardcoded_string': {
                'regex': r'["\'][A-Za-z0-9+/=]{20,}["\']',
                'description': 'Long hardcoded strings (potential secrets)',
                'weight': 0.6
            }
        }

    def _get_enhanced_patterns(self) -> Dict[str, Dict]:
        """Enhanced patterns for complex vulnerability detection - Phase A recall improvement"""
        return {
            'complex_sql_injection': {
                'regex': r'SELECT.*FROM.*WHERE.*\+.*\w+|INSERT.*INTO.*VALUES.*\+.*\w+|UPDATE.*SET.*\+.*\w+|query\s*=.*\+|sql\s*=.*\+|query\s*=.*\n.*\+.*\w+|sql\s*=.*\n.*\+.*\w+',
                'description': 'Complex SQL injection with concatenation and multi-line patterns',
                'weight': 0.8,
                'confidence_boost': 0.2
            },
            'fstring_injection': {
                'regex': r'f["\'].*\{.*\}.*["\']|f["\'].*SELECT.*\{.*\}.*["\']|f["\'].*INSERT.*\{.*\}.*["\']|f["\'].*UPDATE.*\{.*\}.*["\']|query\s*=.*f["\'].*\{.*\}|sql\s*=.*f["\'].*\{.*\}|execute.*f["\'].*\{.*\}|f["\'][\s\S]*?\{[\s\S]*?\}[\s\S]*?["\']',
                'description': 'F-string SQL injection patterns',
                'weight': 0.85,
                'confidence_boost': 0.25
            },
            'template_literal_injection': {
                'regex': r'`.*\$\{.*\}.*`|innerHTML.*`.*\$\{.*\}.*`|document\.write.*`.*\$\{.*\}.*`|html\s*=.*`.*\$\{.*\}|element\.innerHTML\s*=.*`.*\$\{.*\}|response\.send.*`.*\$\{.*\}|`[\s\S]*?\$\{[\s\S]*?\}[\s\S]*?`',
                'description': 'JavaScript template literal XSS patterns',
                'weight': 0.9,
                'confidence_boost': 0.3
            },
            'multi_line_command_injection': {
                'regex': r'subprocess\..*\[.*\+.*\]|os\.system.*\+|exec.*\+|cmd\s*=.*\+|command\s*=.*\+|os\.popen.*\+|cmd\s*=.*\n.*\+.*\w+|command\s*=.*\n.*\+.*\w+',
                'description': 'Multi-line command injection patterns',
                'weight': 0.85,
                'confidence_boost': 0.25
            },
            'complex_path_traversal': {
                'regex': r'open.*\+.*\w+|File\(.*\+.*\)|Path\..*\+.*\w+|filename\s*=.*\+|filepath\s*=.*\+|file\s*=.*\+|path\s*=.*\n.*\+.*\w+|filepath\s*=.*\n.*\+.*\w+',
                'description': 'Complex path traversal with concatenation',
                'weight': 0.8,
                'confidence_boost': 0.2
            },
            'dynamic_eval_injection': {
                'regex': r'eval\s*\(.*\+.*\)|exec\s*\(.*\+.*\)|Function\s*\(.*\+.*\)|code\s*=.*\+|script\s*=.*\+|eval\(.*\+.*\w+|code\s*=.*\n.*\+.*\w+|script\s*=.*\n.*\+.*\w+',
                'description': 'Dynamic code evaluation injection patterns',
                'weight': 1.0,
                'confidence_boost': 0.35
            },
            'reflection_injection': {
                'regex': r'Class\.forName\s*\(.*\+.*\)|Method.*getMethod\s*\(.*\+.*\)|getattr\s*\(.*\+.*\)|setattr\s*\(.*\+.*\)|class_name\s*=.*\+|method_name\s*=.*\+|attr_name\s*=.*\+|class_name\s*=.*\n.*\+.*\w+|method_name\s*=.*\n.*\+.*\w+',
                'description': 'Reflection and dynamic attribute injection',
                'weight': 0.9,
                'confidence_boost': 0.3
            }
        }
