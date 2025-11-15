"""
Static Analysis Scanner - Detects security vulnerabilities in code
Multi-language support with dedicated analyzers for each language.
"""

import re
import ast
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import hashlib

# Import multi-language support
from .language_support import (
    get_language_from_file,
    get_analyzer,
    LANGUAGE_ANALYZERS,
    FILE_EXTENSIONS
)

# 🚀 PERFORMANCE OPTIMIZATIONS
from .streaming_processor import StreamingFileProcessor, SmartFilePreFilter
from .cache_system import cache_system, generate_file_fingerprint
from .detectors.base_detector import regex_pool

# ML-based false positive reduction
try:
    from .ml_false_positive_reducer import MLFalsePositiveReducer
    ML_FPR_AVAILABLE = True
except ImportError:
    ML_FPR_AVAILABLE = False
    MLFalsePositiveReducer = None

# Import CWE expansion detectors
# Note: This is imported lazily in __init__ to avoid circular imports
CWE_EXPANSION_AVAILABLE = False
get_all_cwe_expansion_detectors = None

def _load_cwe_expansion():
    """Lazy load CWE expansion detectors to avoid circular imports"""
    global CWE_EXPANSION_AVAILABLE, get_all_cwe_expansion_detectors
    if not CWE_EXPANSION_AVAILABLE:
        try:
            from .detectors.cwe_expansion import get_all_cwe_expansion_detectors as _get_all
            get_all_cwe_expansion_detectors = _get_all
            CWE_EXPANSION_AVAILABLE = True
        except (ImportError, SyntaxError, AttributeError):
            CWE_EXPANSION_AVAILABLE = False
            get_all_cwe_expansion_detectors = None
    return CWE_EXPANSION_AVAILABLE


@dataclass(frozen=True)
class Vulnerability:
    """Represents a detected security vulnerability"""
    cwe: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: str = "high"
    category: str = "security"
    language: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary"""
        return asdict(self)


class Scanner:
    """Main scanner class for detecting security vulnerabilities"""
    
    def __init__(self, exclude_patterns: Optional[List[str]] = None, languages: Optional[List[str]] = None):
        self.exclude_patterns = exclude_patterns or [
            # Version control
            ".git/**",
            ".svn/**",
            ".hg/**",
            ".bzr/**",

            # Python environments and cache
            "venv/**",
            ".venv/**",
            "__pycache__/**",
            "*.pyc",
            "*.pyo",
            "*.pyd",
            ".Python/**",
            "pip-log.txt",
            "pip-delete-this-directory.txt",

            # Node.js
            "node_modules/**",
            "npm-debug.log*",
            "yarn-debug.log*",
            "yarn-error.log*",
            "*.min.js",
            "*.min.css",

            # Java/Maven/Gradle
            "target/**",
            ".gradle/**",
            "build/**",
            ".class/**",
            "*.class",

            # .NET
            "bin/**",
            "obj/**",
            ".vs/**",
            "*.user",

            # Go
            "vendor/**",

            # Rust
            "target/**",
            "Cargo.lock",

            # IDE and editor files
            ".vscode/**",
            ".idea/**",
            "*.swp",
            "*.swo",
            "*~",

            # OS files
            ".DS_Store",
            "Thumbs.db",

            # Build and dist directories
            "dist/**",
            "out/**",
            "release/**",

            # Test files and coverage
            "coverage/**",
            ".coverage/**",
            "*.test.*",
            "*.spec.*",
            "test-results/**",

            # Documentation and assets
            "docs/_build/**",
            "site/**",

            # Temporary files
            "*.tmp",
            "*.temp",
            ".tmp/**",
            ".temp/**",
        ]

        # Filter languages if specified
        self.languages = languages or list(LANGUAGE_ANALYZERS.keys())

        # 🚀 PERFORMANCE OPTIMIZATIONS
        self.streaming_processor = StreamingFileProcessor()
        self.pre_filter = SmartFilePreFilter()
        
        # Legacy detectors for backward compatibility
        self.detectors = [
            SQLInjectionDetector(),
            XSSDetector(),
            SecretsDetector(),
            PathTraversalDetector(),
            CommandInjectionDetector(),
            DeserializationDetector(),
            WeakCryptoDetector(),
            XXEDetector(),
            SSRFDetector(),
            PermissionDetector(),
        ]
        
        # Add comprehensive CWE expansion detectors (200+ CWEs)
        # Load lazily to avoid circular import issues
        # TEMPORARILY DISABLED: CWE expansion detectors have syntax errors and cause false positives
        # if _load_cwe_expansion() and get_all_cwe_expansion_detectors:
        #     try:
        #         cwe_expansion_detectors = get_all_cwe_expansion_detectors()
        #         self.detectors.extend(cwe_expansion_detectors)
        #     except Exception as e:
        #         # If CWE expansion fails to load, continue with legacy detectors
        #         pass

        # Initialize custom rules engine
        self.custom_rules_engine = None
        self._load_custom_rules()

        # Initialize ML false positive reducer
        self.ml_fpr = None
        if ML_FPR_AVAILABLE:
            try:
                self.ml_fpr = MLFalsePositiveReducer()
            except Exception:
                self.ml_fpr = None

    def _load_custom_rules(self):
        """Load custom security rules"""
        try:
            from .custom_rules import CustomRulesEngine
            self.custom_rules_engine = CustomRulesEngine()
            self.custom_rules_engine.load_rules()
        except Exception as e:
            # Custom rules are optional, continue without them
            pass

    def scan(self, path, mode: str = "fast") -> Dict[str, Any]:
        """
        Scan a file or directory for vulnerabilities

        Args:
            path: Path to file or directory to scan (string or Path object)
            mode: Scan mode - "fast" (pattern only) or "hybrid" (pattern + AI)

        Returns:
            Dictionary containing scan results and vulnerabilities
        """
        vulnerabilities = []
        files_scanned = 0

        # Convert string to Path if needed
        if isinstance(path, str):
            path = Path(path)

        # Check if path exists
        if not path.exists():
            raise FileNotFoundError("Path does not exist")

        if path.is_file():
            files = [path]
        else:
            files = self._get_scannable_files(path)

        # For hybrid mode, we need two phases:
        # Phase 1: Pattern-based detection on all files
        # Phase 2: AI analysis only on files with pattern findings
        if mode == "hybrid":
            # Phase 1: Fast pattern detection
            pattern_results = []
            files_with_findings = []

            for file_path in files:
                files_scanned += 1
                file_vulns = self._scan_file_fast_only(file_path)
                pattern_results.extend(file_vulns)
                if file_vulns:  # Only run AI on files with pattern findings
                    files_with_findings.append(file_path)

            # Phase 2: AI analysis on files with pattern findings
            ai_vulns = self._scan_files_with_ai(files_with_findings, pattern_results)

            # Combine results
            vulnerabilities = pattern_results + ai_vulns
        else:
            # Fast mode: pattern detection only
            for file_path in files:
                files_scanned += 1
                file_vulns = self._scan_file_fast_only(file_path)
                vulnerabilities.extend(file_vulns)

        # Apply ML-based false positive reduction
        # TEMPORARILY DISABLED for testing
        # if self.ml_fpr and vulnerabilities:
        #     try:
        #         # Convert to dict format for ML processing
        #         vuln_dicts = [v.to_dict() if hasattr(v, 'to_dict') else v for v in vulnerabilities]
        #         filtered_vulns = self.ml_fpr.reduce_false_positives(vuln_dicts, str(path))
        #
        #         # Convert back to Vulnerability objects
        #         vulnerabilities = []
        #         for v in filtered_vulns:
        #             if isinstance(v, dict):
        #                 vulnerabilities.append(Vulnerability(**v))
        #             else:
        #                 vulnerabilities.append(v)
        #
        #         print(f"ML FPR: Reduced {len(vuln_dicts)} to {len(vulnerabilities)} vulnerabilities")
        #     except Exception as e:
        #         print(f"ML FPR failed: {e}")

        return {
            "scan_id": hashlib.sha256(str(path).encode()).hexdigest()[:12],
            "target": str(path),
            "files_scanned": files_scanned,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }
    
    def _get_scannable_files(self, directory: Path) -> List[Path]:
        """Get list of files to scan, excluding patterns efficiently"""
        files = []

        # Supported file extensions
        extensions = set(FILE_EXTENSIONS.keys())

        # Directories to skip entirely for performance
        skip_dirs = {
            '.git', '.svn', '.hg', '.bzr',
            'venv', '.venv', '__pycache__',
            'node_modules', 'target', 'build', 'bin', 'obj',
            '.gradle', '.vscode', '.idea', '.vs',
            'vendor', 'dist', 'out', 'coverage', '.coverage',
            'complex_test_codebase', 'fair_benchmark_output', 'benchmark_output'
        }

        def scan_directory(dir_path: Path):
            """Recursively scan directory while skipping excluded dirs"""
            try:
                for item in dir_path.iterdir():
                    # Skip entire directories early for massive performance boost
                    if item.is_dir():
                        if item.name in skip_dirs:
                            continue  # Skip this entire directory tree
                        # Check exclude patterns for directories
                        if any(item.match(pattern) for pattern in self.exclude_patterns):
                            continue
                        # Recursively scan subdirectory
                        scan_directory(item)
                    elif item.is_file() and item.suffix in extensions:
                        # Check file-level exclusions
                        if not any(item.match(pattern) for pattern in self.exclude_patterns):
                            files.append(item)
            except (PermissionError, OSError):
                # Skip directories we can't read
                pass

        scan_directory(directory)
        return files
    
    def _scan_file_fast_only(self, file_path: Path) -> List[Vulnerability]:
        """
        🚀 FAST MODE: Scan file with pattern-based detection only (no AI, no streaming)
        """
        vulnerabilities = []

        # 🚀 Pre-filtering: Skip obviously irrelevant files
        should_analyze, reason = self.pre_filter.should_analyze_file(file_path)
        if not should_analyze:
            return []

        try:
            # 🚀 CACHING: Check if file has been analyzed recently
            fingerprint = generate_file_fingerprint(file_path)
            cache_key = f"fast:{fingerprint}"

            cached_result = cache_system.get(cache_key)
            if cached_result is not None:
                # Cache hit - return cached vulnerabilities
                return cached_result

            # Detect file language
            language = get_language_from_file(str(file_path))

            # Skip if language not supported
            if language == 'unknown' or language not in self.languages:
                # Fall back to legacy detectors for unsupported languages
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")
                for detector in self.detectors:
                    vulns = detector.detect(file_path, content, lines)
                    vulnerabilities.extend(vulns)
            else:
                # Use language-specific analyzer for supported languages
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                # PRIMARY: Use language-specific analyzer
                analyzer = get_analyzer(language)
                if analyzer:
                    lang_vulns = analyzer.analyze(content, str(file_path))
                    # Convert to Scanner Vulnerability format
                    for vuln in lang_vulns:
                        vulnerabilities.append(Vulnerability(
                            cwe=vuln.cwe,
                            severity=vuln.severity,
                            title=vuln.title,
                            description=vuln.description,
                            file_path=vuln.file_path,
                            line_number=vuln.line_number,
                            code_snippet=vuln.code_snippet,
                            confidence=vuln.confidence,
                            category="security",
                            language=language
                        ))

                # SECONDARY: Also run legacy detectors for comprehensive coverage
                lines = content.split("\n")
                for detector in self.detectors:
                    vulns = detector.detect(file_path, content, lines)
                    vulnerabilities.extend(vulns)

            # Check custom rules
            if self.custom_rules_engine:
                custom_violations = self.custom_rules_engine.check_file(file_path, content, language)
                for violation in custom_violations:
                    vulnerabilities.append(Vulnerability(
                        cwe=violation.get('metadata', {}).get('cwe', 'CWE-CUSTOM'),
                        severity=violation['severity'],
                        title=f"Custom Rule: {violation['rule_id']}",
                        description=violation['message'],
                        file_path=violation['file'],
                        line_number=violation['line'],
                        code_snippet=violation['matched_text'],
                        confidence="high",
                        category="custom",
                        language=language
                    ))

        except Exception as e:
            # Skip files that can't be read
            pass

        # 🚀 CACHING: Store successful analysis results
        cache_system.set(cache_key, vulnerabilities, ttl=3600)  # 1 hour cache

        return vulnerabilities

    def _scan_files_with_ai(self, files_with_findings: List[Path], pattern_results: List[Vulnerability]) -> List[Vulnerability]:
        """
        🚀 HYBRID MODE: Run AI analysis only on files that had pattern findings
        """
        ai_vulns = []

        if not files_with_findings:
            return ai_vulns

        # Check if AI is available
        try:
            from .ai_detector import AIDetector
            import multiprocessing

            # 🚀 HYBRID SPEEDUP: Parallel AI processing
            max_workers = min(multiprocessing.cpu_count() or 8, 8)
            ai_detector = AIDetector(max_workers=max_workers)

            # Process files with AI
            def process_file_ai(file_path):
                """Process single file with AI detection"""
                try:
                    code = file_path.read_text(errors='ignore')
                    language = get_language_from_file(str(file_path))

                    # 🚀 HYBRID: Run AI on all files with pattern findings (don't skip based on confidence)
                    # The confidence score is used for result filtering, not exclusion

                    # Get existing pattern findings for this file
                    file_pattern_vulns = [v for v in pattern_results if v.file_path == str(file_path)]

                    # Enhanced AI detection with context
                    file_vulns = ai_detector.detect_vulnerabilities(
                        code, str(file_path), language, line_number=None
                    )

                    # RAG-enhanced detection for additional vulnerabilities
                    rag_vulns = ai_detector.find_additional_vulnerabilities_rag(
                        code, str(file_path), language, file_vulns
                    )
                    file_vulns.extend(rag_vulns)

                    # Filter AI results by confidence
                    high_confidence_vulns = [
                        v for v in file_vulns
                        if getattr(v, 'confidence', 'medium') in ['high', 'medium']
                    ]

                    # Convert to Vulnerability objects
                    scanner_vulns = []
                    for vuln in high_confidence_vulns:
                        if hasattr(vuln, 'to_dict'):
                            vuln_dict = vuln.to_dict()
                        else:
                            vuln_dict = vuln

                        scanner_vulns.append(Vulnerability(
                            cwe=vuln_dict.get('cwe', 'CWE-AI'),
                            severity=vuln_dict.get('severity', 'medium'),
                            title=vuln_dict.get('title', 'AI-Detected Vulnerability'),
                            description=vuln_dict.get('description', ''),
                            file_path=vuln_dict.get('file_path', str(file_path)),
                            line_number=vuln_dict.get('line_number', 1),
                            code_snippet=vuln_dict.get('code_snippet', ''),
                            confidence=vuln_dict.get('confidence', 'medium'),
                            category="ai-detected",
                            language=language
                        ))

                    return scanner_vulns

                except Exception as e:
                    return []

            # TEMPORARILY RUN SYNCHRONOUSLY for debugging
            for file_path in files_with_findings:
                try:
                    file_ai_vulns = process_file_ai(file_path)
                    ai_vulns.extend(file_ai_vulns)
                except Exception as e:
                    continue

        except Exception as e:
            # AI not available, return empty
            pass

        return ai_vulns

    def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """
        🚀 PERFORMANCE OPTIMIZATION: Scan file with streaming and caching
        """
        vulnerabilities = []

        # 🚀 Pre-filtering: Skip obviously irrelevant files
        should_analyze, reason = self.pre_filter.should_analyze_file(file_path)
        if not should_analyze:
            return []

        try:
            # 🚀 CACHING: Check if file has been analyzed recently
            fingerprint = generate_file_fingerprint(file_path)
            cache_key = f"scan:{fingerprint}"

            cached_result = cache_system.get(cache_key)
            if cached_result is not None:
                # Cache hit - return cached vulnerabilities
                return cached_result

            # Detect file language
            language = get_language_from_file(str(file_path))

            # Skip if language not supported or not in filter
            if language == 'unknown' or language not in self.languages:
                # Fall back to legacy detectors for unsupported languages
                # 🚀 STREAMING: Use streaming processor for large files
                def analyze_chunk(chunk_text: str, file_path: Path, offset: int) -> List[Vulnerability]:
                    # For legacy detectors, we need full content
                    return []

                result = self.streaming_processor.process_file_streaming(
                    file_path, analyze_chunk, early_exit_threshold=50
                )

                if result.early_termination:
                    # File too large or binary, skip
                    return []

                # Fall back to full read for legacy detectors
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")
                for detector in self.detectors:
                    vulns = detector.detect(file_path, content, lines)
                    vulnerabilities.extend(vulns)

                # 🚀 CACHING: Store result
                cache_system.set(cache_key, vulnerabilities, ttl=3600)  # 1 hour
                return vulnerabilities

            # 🚀 STREAMING: Use streaming analysis for supported languages
            def analyze_chunk_streaming(chunk_text: str, file_path: Path, offset: int) -> List[Vulnerability]:
                """Analyze file chunks for vulnerabilities"""
                chunk_vulns = []

                # Get language-specific analyzer
                analyzer = get_analyzer(language)
                if analyzer:
                    # Analyze this chunk
                    try:
                        lang_vulns = analyzer.analyze(chunk_text, str(file_path))

                        # Adjust line numbers based on chunk offset
                        for vuln in lang_vulns:
                            # Estimate line number from offset (rough approximation)
                            estimated_lines = chunk_text[:offset].count('\n') if offset > 0 else 0
                            vuln.line_number += estimated_lines

                            chunk_vulns.append(Vulnerability(
                                cwe=vuln.cwe,
                                severity=vuln.severity,
                                title=vuln.title,
                                description=vuln.description,
                                file_path=vuln.file_path,
                                line_number=vuln.line_number,
                                code_snippet=vuln.code_snippet,
                                confidence=vuln.confidence,
                                category="security",
                                language=language
                            ))
                    except Exception:
                        # Chunk analysis failed, will fall back to full analysis
                        pass

                return chunk_vulns

            # Always read full content for comprehensive analysis
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # PRIMARY: Use language-specific analyzer (highest priority for accuracy)
            analyzer = get_analyzer(language)
            if analyzer:
                # Use new language-specific analyzer on full content
                lang_vulns = analyzer.analyze(content, str(file_path))

                # Convert to Scanner Vulnerability format
                for vuln in lang_vulns:
                    vulnerabilities.append(Vulnerability(
                        cwe=vuln.cwe,
                        severity=vuln.severity,
                        title=vuln.title,
                        description=vuln.description,
                        file_path=vuln.file_path,
                        line_number=vuln.line_number,
                        code_snippet=vuln.code_snippet,
                        confidence=vuln.confidence,
                        category="security",
                        language=language
                    ))

            # DISABLE streaming analysis for now to ensure analyzer priority
            # Streaming can be re-enabled later for large file optimization
            # streaming_result = self.streaming_processor.process_file_streaming(
            #     file_path, analyze_chunk_streaming, early_exit_threshold=50
            # )
            # if streaming_result.vulnerabilities:
            #     vulnerabilities.extend(streaming_result.vulnerabilities)
            else:
                # Fall back to legacy detectors
                lines = content.split("\n")
                for detector in self.detectors:
                    vulns = detector.detect(file_path, content, lines)
                    vulnerabilities.extend(vulns)

            # Check custom rules
            if self.custom_rules_engine:
                custom_violations = self.custom_rules_engine.check_file(file_path, content, language)
                for violation in custom_violations:
                    vulnerabilities.append(Vulnerability(
                        cwe=violation.get('metadata', {}).get('cwe', 'CWE-CUSTOM'),
                        severity=violation['severity'],
                        title=f"Custom Rule: {violation['rule_id']}",
                        description=violation['message'],
                        file_path=violation['file'],
                        line_number=violation['line'],
                        code_snippet=violation['matched_text'],
                        confidence="high",
                        category="custom",
                        language=language
                    ))

        except Exception as e:
            # Skip files that can't be read
            pass

        # 🚀 CACHING: Store successful analysis results
        cache_system.set(cache_key, vulnerabilities, ttl=3600)  # 1 hour cache

        return vulnerabilities


class VulnerabilityDetector:
    """Base class for vulnerability detectors"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """Detect vulnerabilities in file content"""
        raise NotImplementedError


class SQLInjectionDetector(VulnerabilityDetector):
    """Detects SQL injection vulnerabilities (CWE-89)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Python patterns
        py_patterns = [
            r'execute\s*\(\s*["\'].*%s.*["\'].*%',
            r'execute\s*\(\s*f["\'].*\{.*\}',
            r'execute\s*\(\s*["\'].*\+.*\+',
            r'cursor\.execute\s*\([^)]*\+',
            r'\.raw\s*\([^)]*\+',
        ]
        
        # JavaScript/TypeScript patterns
        js_patterns = [
            r'query\s*\([^)]*\+.*\+',
            r'execute\s*\(`.*\$\{',
            r'\.query\s*\(["\'].*\$\{',
        ]
        
        all_patterns = py_patterns + js_patterns
        
        for i, line in enumerate(lines, 1):
            for pattern in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-89",
                        severity="high",
                        title="SQL Injection",
                        description="Potential SQL injection vulnerability detected. User input appears to be concatenated directly into SQL query.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="medium",
                        category="injection"
                    ))
        
        return vulnerabilities


class XSSDetector(VulnerabilityDetector):
    """Detects Cross-Site Scripting vulnerabilities (CWE-79)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        base_patterns = [
            re.compile(r'innerHTML\s*=', re.IGNORECASE),
            re.compile(r'document\.write\s*\(', re.IGNORECASE),
            re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE),
            re.compile(r'\.html\s*\([^)]*\+', re.IGNORECASE),
            re.compile(r'<script>.*\{.*\}.*</script>', re.IGNORECASE),
        ]

        python_source_patterns = [
            re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*request\.(?:args|form|values)\.get', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*request\.(GET|POST)\[', re.IGNORECASE),
        ]

        js_source_patterns = [
            re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req\.(?:query|body|params)\.', re.IGNORECASE),
            re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req\.getParameter\(', re.IGNORECASE),
        ]

        tainted_vars: Dict[str, int] = {}

        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            for pattern in python_source_patterns + js_source_patterns:
                match = pattern.search(line)
                if match:
                    tainted_vars[match.group(1)] = index

            emitted = False
            for pattern in base_patterns:
                if pattern.search(line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description="Potential XSS vulnerability. User input may be rendered without proper sanitization.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))
                    emitted = True
                    break

            if emitted:
                continue

            lower_line = line.lower()
            js_sink = re.search(r'\b(res|response)\.(send|write)\s*\(', lower_line)
            if js_sink:
                if any(f'${{{var}' in line or f'+ {var}' in line or f'{var} +' in line for var in tainted_vars):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description="User-controlled data appears in an HTML response without escaping.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))
                    continue

            if ('return' in lower_line or 'render_template_string' in lower_line) and ('f"' in line or "f'" in line):
                if any(f'{{{var}' in line for var in tainted_vars):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description="User-controlled data appears in HTML output without escaping.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))
                    continue

            if re.search(r'return\s+"[^"]*"\s*\+\s*', line) or re.search(r"return\s+'[^']*'\s*\+\s*", line):
                if any(re.search(fr'\b{var}\b', line) for var in tainted_vars):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description="User-controlled data appears in HTML output without escaping.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))

        return vulnerabilities


class SecretsDetector(VulnerabilityDetector):
    """Detects hardcoded secrets and credentials (CWE-798)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', "password"),
            (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']{10,}["\']', "API key"),
            (r'(?i)(secret[_-]?key|secretkey)\s*=\s*["\'][^"\']{10,}["\']', "secret key"),
            (r'(?i)(token)\s*=\s*["\'][^"\']{20,}["\']', "token"),
            (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*["\'][A-Z0-9]{20}["\']', "AWS key"),
            (r'(?i)(private[_-]?key)\s*=\s*["\']-----BEGIN', "private key"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, secret_type in patterns:
                if re.search(pattern, line):
                    # Skip if it looks like a placeholder
                    if any(placeholder in line.lower() for placeholder in 
                           ["example", "placeholder", "dummy", "test", "xxx", "***"]):
                        continue
                    
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-798",
                        severity="critical",
                        title="Hardcoded Credentials",
                        description=f"Hardcoded {secret_type} detected. Credentials should be stored in environment variables or secure vaults.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=self._redact_secret(line.strip()),
                        confidence="high",
                        category="secrets"
                    ))
        
        return vulnerabilities
    
    def _redact_secret(self, line: str) -> str:
        """Redact the actual secret value"""
        return re.sub(r'["\'][^"\']{3,}["\']', '"***REDACTED***"', line)


class PathTraversalDetector(VulnerabilityDetector):
    """Detects path traversal vulnerabilities (CWE-22)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        base_patterns = [
            re.compile(r'open\s*\([^)]*\+', re.IGNORECASE),
            re.compile(r'readFile\s*\([^)]*\+', re.IGNORECASE),
            re.compile(r'readFileSync\s*\([^)]*\+', re.IGNORECASE),
            re.compile(r'File\s*\([^)]*\+', re.IGNORECASE),
            re.compile(r'\.read\s*\([^)]*\+', re.IGNORECASE),
        ]

        python_source_patterns = [
            re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*request\.(?:args|form|values)\.get', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*request\.(GET|POST)\[', re.IGNORECASE),
        ]

        js_source_patterns = [
            re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req\.(?:query|body|params)\.', re.IGNORECASE),
            re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*req\.getParameter\(', re.IGNORECASE),
        ]

        tainted_vars: Dict[str, int] = {}

        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            for pattern in python_source_patterns + js_source_patterns:
                match = pattern.search(line)
                if match:
                    tainted_vars[match.group(1)] = index

            emitted = False
            for pattern in base_patterns:
                if pattern.search(line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-22",
                        severity="high",
                        title="Path Traversal",
                        description="Potential path traversal vulnerability. File paths should be validated to prevent directory traversal attacks.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))
                    emitted = True
                    break

            if emitted:
                continue

            if 'open(' in line or 'os.path.join' in line or 'Path(' in line:
                if any(f'{{{var}' in line or re.search(fr'\b{var}\b', line) for var in tainted_vars):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-22",
                        severity="high",
                        title="Path Traversal",
                        description="User-controlled path appears in file system access.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))
                    continue

            if re.search(r'fs\.(readFile|createReadStream|readFileSync)\s*\(', line, re.IGNORECASE):
                if any(re.search(fr'\b{var}\b', line) for var in tainted_vars):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-22",
                        severity="high",
                        title="Path Traversal",
                        description="User-controlled file path appears in file system access.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=line,
                        confidence="medium",
                        category="injection"
                    ))

        return vulnerabilities


class CommandInjectionDetector(VulnerabilityDetector):
    """Detects OS command injection vulnerabilities (CWE-78)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            r'os\.system\s*\([^)]*\+',
            r'subprocess\.call\s*\([^)]*\+',
            r'exec\s*\([^)]*\+',
            r'eval\s*\([^)]*\+',
            r'shell_exec\s*\([^)]*\+',
            r'system\s*\([^)]*\$',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-78",
                        severity="critical",
                        title="OS Command Injection",
                        description="Potential command injection vulnerability. User input should never be passed directly to system commands.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="high",
                        category="injection"
                    ))
        
        return vulnerabilities


class DeserializationDetector(VulnerabilityDetector):
    """Detects unsafe deserialization (CWE-502)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^,)]*\)',
            r'unserialize\s*\(',
            r'JSON\.parse\s*\([^)]*\+',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-502",
                        severity="high",
                        title="Unsafe Deserialization",
                        description="Unsafe deserialization detected. Deserializing untrusted data can lead to remote code execution.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="medium",
                        category="deserialization"
                    ))
        
        return vulnerabilities


class WeakCryptoDetector(VulnerabilityDetector):
    """Detects weak cryptographic algorithms (CWE-327)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            (r'\.md5\s*\(', "MD5"),
            (r'\.sha1\s*\(', "SHA-1"),
            (r'hashlib\.md5', "MD5"),
            (r'hashlib\.sha1', "SHA-1"),
            (r'DES\s*\(', "DES"),
            (r'Cipher\.MODE_ECB', "ECB mode"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, algo in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-327",
                        severity="medium",
                        title="Weak Cryptographic Algorithm",
                        description=f"Weak cryptographic algorithm detected: {algo}. Use SHA-256 or stronger algorithms.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="high",
                        category="cryptography"
                    ))
        
        return vulnerabilities


class XXEDetector(VulnerabilityDetector):
    """Detects XML External Entity vulnerabilities (CWE-611)"""

    SOURCE_PATTERNS = [
        re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*request\.(?:data|body|get_data)\b', re.IGNORECASE),
        re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*req\.(?:body|rawBody|files)\b', re.IGNORECASE),
        re.compile(r'\b([A-Za-z_][\w]*)\s*=\s*context\.get(?:String|Bytes)Extra\(', re.IGNORECASE),
    ]

    SINK_PATTERNS = [
        re.compile(r'ET\.(fromstring|parse)\s*\(', re.IGNORECASE),
        re.compile(r'ElementTree\.(fromstring|parse)\s*\(', re.IGNORECASE),
        re.compile(r'xmltodict\.parse\s*\(', re.IGNORECASE),
        re.compile(r'minidom\.(parse|parseString)\s*\(', re.IGNORECASE),
        re.compile(r'SAXParser\s*\(', re.IGNORECASE),
        re.compile(r'DocumentBuilderFactory\.[^;]*newDocumentBuilder\(\)', re.IGNORECASE),
    ]

    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        tainted_vars: Dict[str, int] = {}

        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            for pattern in self.SOURCE_PATTERNS:
                match = pattern.search(line)
                if match:
                    tainted_vars[match.group(1)] = index

            for sink in self.SINK_PATTERNS:
                if not sink.search(line):
                    continue

                if any(keyword in line for keyword in ('resolve_entities=False', 'defusedxml', 'no_network=True')):
                    continue

                is_tainted = any(var in line for var in tainted_vars)
                if not is_tainted:
                    context = '\n'.join(lines[max(0, index - 3): index + 2]).lower()
                    is_tainted = any(token in context for token in ('request.data', 'request.body', 'req.body', 'req.rawbody'))

                if is_tainted:
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-611",
                        severity="high",
                        title="XML External Entity (XXE)",
                        description="XML parsing of user-controlled input without disabling external entities.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=raw_line.strip(),
                        confidence="medium",
                        category="xml"
                    ))

        return vulnerabilities


class SSRFDetector(VulnerabilityDetector):
    """Detects Server-Side Request Forgery (CWE-918)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        tainted_vars: Dict[str, int] = {}

        source_patterns = [
            re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*request\.(?:args|form|values|get_json)\b', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*request\.(?:GET|POST)\[', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*req\.(?:query|body|params)\.', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*req\.getParameter\(', re.IGNORECASE),
            re.compile(r'\b([A-Za-z_$][\w$]*)\s*=\s*context\.getStringExtra\(', re.IGNORECASE),
        ]

        sink_patterns = [
            re.compile(r'requests\.(get|post|put|delete|request)\s*\(', re.IGNORECASE),
            re.compile(r'httpx\.(get|post)\s*\(', re.IGNORECASE),
            re.compile(r'urllib\.request\.(urlopen|Request)\s*\(', re.IGNORECASE),
            re.compile(r'fetch\s*\(', re.IGNORECASE),
            re.compile(r'axios\.(get|post|request)\s*\(', re.IGNORECASE),
            re.compile(r'http\.get\s*\(', re.IGNORECASE),
            re.compile(r'WebClient\.(create|builder)\(', re.IGNORECASE),
        ]

        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            for pattern in source_patterns:
                match = pattern.search(line)
                if match:
                    tainted_vars[match.group(1)] = index

            for sink in sink_patterns:
                if not sink.search(line):
                    continue

                inlined = any(keyword in line for keyword in (
                    'request.args', 'request.form', 'request.GET', 'request.POST', 'req.query', 'req.body', 'req.params', 'req.getParameter'
                ))
                referenced = any(var in line for var in tainted_vars)

                if inlined or referenced:
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-918",
                        severity="high",
                        title="Server-Side Request Forgery (SSRF)",
                        description="External request appears to use user-controlled input without validation.",
                        file_path=str(file_path),
                        line_number=index,
                        code_snippet=raw_line.strip(),
                        confidence="medium",
                        category="injection"
                    ))

        return vulnerabilities


class PermissionDetector(VulnerabilityDetector):
    """Detects incorrect permission assignments (CWE-732)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            (r'chmod\s*\(\s*[^,)]*\s*,\s*0?777', "777 (world-writable)"),
            (r'os\.chmod\s*\([^,)]*,\s*0o777', "777 (world-writable)"),
            (r'umask\s*\(\s*0+\s*\)', "000 (no restrictions)"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, perm in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-732",
                        severity="medium",
                        title="Incorrect Permission Assignment",
                        description=f"Overly permissive file permissions: {perm}. Files should use restrictive permissions.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="high",
                        category="permissions"
                    ))
        
        return vulnerabilities

