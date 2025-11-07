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
        if _load_cwe_expansion() and get_all_cwe_expansion_detectors:
            try:
                cwe_expansion_detectors = get_all_cwe_expansion_detectors()
                self.detectors.extend(cwe_expansion_detectors)
            except Exception as e:
                # If CWE expansion fails to load, continue with legacy detectors
                pass

        # Initialize custom rules engine
        self.custom_rules_engine = None
        self._load_custom_rules()

    def _load_custom_rules(self):
        """Load custom security rules"""
        try:
            from .custom_rules import CustomRulesEngine
            self.custom_rules_engine = CustomRulesEngine()
            self.custom_rules_engine.load_rules()
        except Exception as e:
            # Custom rules are optional, continue without them
            pass

    def scan(self, path: Path) -> Dict[str, Any]:
        """
        Scan a file or directory for vulnerabilities
        
        Args:
            path: Path to file or directory to scan
            
        Returns:
            Dictionary containing scan results and vulnerabilities
        """
        vulnerabilities = []
        files_scanned = 0
        
        # Check if path exists
        if not path.exists():
            raise FileNotFoundError("Path does not exist")
        
        if path.is_file():
            files = [path]
        else:
            files = self._get_scannable_files(path)
        
        for file_path in files:
            files_scanned += 1
            file_vulns = self._scan_file(file_path)
            vulnerabilities.extend(file_vulns)
        
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

            # Try streaming analysis first
            streaming_result = self.streaming_processor.process_file_streaming(
                file_path, analyze_chunk_streaming, early_exit_threshold=20
            )

            if streaming_result.vulnerabilities:
                vulnerabilities = streaming_result.vulnerabilities
            else:
                # Fall back to full file analysis if streaming didn't find anything
                # or if file is small enough for full analysis
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            
            # Get language-specific analyzer
            analyzer = get_analyzer(language)
            if analyzer:
                # Use new language-specific analyzer
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
        vulnerabilities = []
        
        patterns = [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'dangerouslySetInnerHTML',
            r'\.html\s*\([^)]*\+',
            r'<script>.*\{.*\}.*</script>',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description="Potential XSS vulnerability. User input may be rendered without proper sanitization.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
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
        vulnerabilities = []
        
        patterns = [
            r'open\s*\([^)]*\+',
            r'readFile\s*\([^)]*\+',
            r'readFileSync\s*\([^)]*\+',
            r'File\s*\([^)]*\+',
            r'\.read\s*\([^)]*\+',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-22",
                        severity="high",
                        title="Path Traversal",
                        description="Potential path traversal vulnerability. File paths should be validated to prevent directory traversal attacks.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
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
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            r'parse\s*\([^)]*xml',
            r'XMLParser\s*\(',
            r'etree\.parse\s*\(',
            r'ElementTree\.parse\s*\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if safe parsing is used
                    if "resolve_entities=False" in line or "no_network=True" in line:
                        continue
                    
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-611",
                        severity="medium",
                        title="XML External Entity (XXE)",
                        description="Potential XXE vulnerability. XML parsers should disable external entity resolution.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
                        confidence="low",
                        category="injection"
                    ))
        
        return vulnerabilities


class SSRFDetector(VulnerabilityDetector):
    """Detects Server-Side Request Forgery (CWE-918)"""
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        vulnerabilities = []
        
        patterns = [
            r'requests\.get\s*\([^)]*\+',
            r'requests\.post\s*\([^)]*\+',
            r'fetch\s*\([^)]*\+',
            r'urllib\.request\.urlopen\s*\([^)]*\+',
            r'http\.get\s*\([^)]*\+',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-918",
                        severity="high",
                        title="Server-Side Request Forgery (SSRF)",
                        description="Potential SSRF vulnerability. URLs should be validated to prevent requests to internal resources.",
                        file_path=str(file_path),
                        line_number=i,
                        code_snippet=line.strip(),
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

