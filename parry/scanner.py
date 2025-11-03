# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Static Analysis Scanner - Detects security vulnerabilities in code
Multi-language support with dedicated analyzers for each language.

This module provides the core scanning functionality for the Parry Security Scanner.
It includes the main Scanner class, vulnerability data structures, and legacy detector
classes for various security vulnerability types.
"""

# Import regular expression module for pattern matching in code
import re
# Import Abstract Syntax Tree module for parsing Python code structure
import ast
# Import Path for object-oriented filesystem path manipulation
from pathlib import Path
# Import type hints for better code documentation and IDE support
from typing import List, Dict, Any, Optional
# Import dataclass decorator and asdict utility for creating data classes
from dataclasses import dataclass, asdict
# Import hashlib for generating unique scan identifiers
import hashlib

# Import multi-language support modules from the language_support package
from .language_support import (
    get_language_from_file,  # Function to detect programming language from file extension
    get_analyzer,  # Factory function to get language-specific analyzer instance
    LANGUAGE_ANALYZERS,  # Dictionary mapping language names to analyzer classes
    FILE_EXTENSIONS  # Dictionary mapping file extensions to languages
)


@dataclass(frozen=True)  # frozen=True makes instances immutable for thread safety
class Vulnerability:
    """
    Represents a detected security vulnerability
    
    This immutable data class stores all information about a security vulnerability
    found during code scanning, including CWE classification, severity, location,
    and code context.
    """
    # CWE (Common Weakness Enumeration) identifier for the vulnerability type
    cwe: str
    # Severity level: 'low', 'medium', 'high', or 'critical'
    severity: str
    # Short human-readable title describing the vulnerability
    title: str
    # Detailed description explaining the security issue and potential impact
    description: str
    # Path to the file containing the vulnerability
    file_path: str
    # Line number where the vulnerability was detected
    line_number: int
    # The actual code snippet containing the vulnerability
    code_snippet: str
    # Confidence level of the detection: 'low', 'medium', or 'high'
    confidence: str = "high"
    # Category of vulnerability: 'security', 'injection', 'cryptography', etc.
    category: str = "security"
    # Programming language of the vulnerable code
    language: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert vulnerability to dictionary format
        
        Returns:
            Dictionary with all vulnerability attributes for JSON serialization
        """
        # Use dataclass utility to convert to dict, preserving all fields
        return asdict(self)


class Scanner:
    """
    Main scanner class for detecting security vulnerabilities
    
    This class orchestrates the scanning process, managing file discovery,
    language detection, analyzer selection, and vulnerability aggregation.
    It supports both modern language-specific analyzers and legacy pattern-based
    detectors for backward compatibility.
    """
    
    def __init__(self, exclude_patterns: Optional[List[str]] = None, languages: Optional[List[str]] = None):
        """
        Initialize the Scanner with exclusion patterns and language filters
        
        Args:
            exclude_patterns: List of glob patterns for files/directories to exclude from scanning
            languages: List of programming languages to scan (None = all supported languages)
        """
        # Define patterns for files and directories that should not be scanned
        self.exclude_patterns = exclude_patterns or [
            "*/node_modules/*",  # Node.js dependencies directory
            "*/.git/*",  # Git version control directory
            "*/venv/*",  # Python virtual environment directory
            "*/__pycache__/*",  # Python bytecode cache directory
            "*/dist/*",  # Distribution/build output directory
            "*/build/*",  # Build artifacts directory
            "*.min.js",  # Minified JavaScript files (hard to analyze)
            "*.min.css",  # Minified CSS files
            "*/vendor/*",  # Third-party vendor code directory
            "*/target/*",  # Build target directory (Java, Rust)
            "*.test.js",  # JavaScript test files
            "*.spec.js",  # JavaScript specification test files
        ]
        
        # Filter languages if specified, otherwise use all available language analyzers
        self.languages = languages or list(LANGUAGE_ANALYZERS.keys())
        
        # Legacy detectors for backward compatibility with older scanning logic
        # These provide basic pattern-matching for common vulnerabilities
        self.detectors = [
            SQLInjectionDetector(),  # Detects SQL injection vulnerabilities
            XSSDetector(),  # Detects cross-site scripting vulnerabilities
            SecretsDetector(),  # Detects hardcoded credentials and secrets
            PathTraversalDetector(),  # Detects path traversal vulnerabilities
            CommandInjectionDetector(),  # Detects OS command injection
            DeserializationDetector(),  # Detects unsafe deserialization
            WeakCryptoDetector(),  # Detects weak cryptographic algorithms
            XXEDetector(),  # Detects XML external entity vulnerabilities
            SSRFDetector(),  # Detects server-side request forgery
            PermissionDetector(),  # Detects incorrect file permission assignments
        ]
    
    def scan(self, path: Path) -> Dict[str, Any]:
        """
        Scan a file or directory for vulnerabilities
        
        This is the main entry point for scanning. It handles both single files
        and entire directory trees, aggregating all discovered vulnerabilities.
        
        Args:
            path: Path to file or directory to scan
            
        Returns:
            Dictionary containing scan results with:
            - scan_id: Unique identifier for this scan
            - target: The path that was scanned
            - files_scanned: Number of files analyzed
            - vulnerabilities_found: Total count of vulnerabilities
            - vulnerabilities: List of vulnerability dictionaries
        """
        # Initialize list to collect all vulnerabilities found during scan
        vulnerabilities = []
        # Counter for number of files successfully scanned
        files_scanned = 0
        
        # Check if path exists before attempting to scan
        if not path.exists():
            # Raise exception if the specified path doesn't exist
            raise FileNotFoundError(f"Path does not exist: {path}")
        
        # Determine if we're scanning a single file or a directory
        if path.is_file():
            # For single file, create a list with just that file
            files = [path]
        else:
            # For directory, get all scannable files recursively
            files = self._get_scannable_files(path)
        
        # Iterate through each file and scan for vulnerabilities
        for file_path in files:
            # Increment the counter of processed files
            files_scanned += 1
            # Scan the individual file and get list of vulnerabilities
            file_vulns = self._scan_file(file_path)
            # Add all vulnerabilities from this file to the overall list
            vulnerabilities.extend(file_vulns)
        
        # Return comprehensive scan results as a dictionary
        return {
            # Generate unique scan ID by hashing the target path (first 12 chars)
            "scan_id": hashlib.sha256(str(path).encode()).hexdigest()[:12],
            # Store the target path as a string
            "target": str(path),
            # Include count of files that were scanned
            "files_scanned": files_scanned,
            # Include total number of vulnerabilities discovered
            "vulnerabilities_found": len(vulnerabilities),
            # Convert all Vulnerability objects to dictionaries for JSON serialization
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }
    
    def _get_scannable_files(self, directory: Path) -> List[Path]:
        """
        Get list of files to scan, excluding patterns
        
        Recursively walks the directory tree and collects all files with
        supported extensions, while respecting exclusion patterns.
        
        Args:
            directory: Root directory to search for scannable files
            
        Returns:
            List of Path objects representing files to scan
        """
        # Initialize empty list to store file paths
        files = []
        
        # Supported file extensions for security scanning
        extensions = {
            ".py",  # Python source files
            ".js",  # JavaScript source files
            ".ts",  # TypeScript source files
            ".jsx",  # JavaScript JSX (React) files
            ".tsx",  # TypeScript JSX files
            ".java",  # Java source files
            ".go",  # Go source files
            ".rb",  # Ruby source files
            ".php",  # PHP source files
            ".cs",  # C# source files
            ".cpp",  # C++ source files
            ".c",  # C source files
            ".h",  # C/C++ header files
            ".hpp",  # C++ header files
            ".rs",  # Rust source files
            ".swift",  # Swift source files
            ".kt",  # Kotlin source files
            ".sql",  # SQL script files
            ".yaml",  # YAML configuration files
            ".yml",  # YAML configuration files (alternative extension)
            ".json"  # JSON data/configuration files
        }
        
        # Recursively iterate through all files in directory tree
        for file_path in directory.rglob("*"):
            # Check if this is a file (not a directory) and has a supported extension
            if file_path.is_file() and file_path.suffix in extensions:
                # Check exclusion patterns - skip file if it matches any pattern
                if not any(file_path.match(pattern) for pattern in self.exclude_patterns):
                    # File passed all checks, add to list of scannable files
                    files.append(file_path)
        
        # Return the complete list of files to be scanned
        return files
    
    def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """
        Scan a single file for vulnerabilities using language-specific analyzers
        
        This method detects the file's programming language, selects the appropriate
        analyzer, and falls back to legacy pattern-based detectors if needed.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of Vulnerability objects found in the file
        """
        # Initialize empty list to collect vulnerabilities from this file
        vulnerabilities = []
        
        try:
            # Detect file language based on extension and content
            language = get_language_from_file(str(file_path))
            
            # Skip if language not supported or not in filter
            if language == 'unknown' or language not in self.languages:
                # Fall back to legacy detectors for unsupported languages
                # Read the file content, ignoring encoding errors
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                # Split content into individual lines for line-by-line analysis
                lines = content.split("\n")
                # Run each legacy detector on the file
                for detector in self.detectors:
                    # Detect vulnerabilities using pattern matching
                    vulns = detector.detect(file_path, content, lines)
                    # Add detected vulnerabilities to the list
                    vulnerabilities.extend(vulns)
                # Return vulnerabilities found by legacy detectors
                return vulnerabilities
            
            # Read file content for analysis, ignoring any encoding errors
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            
            # Get language-specific analyzer instance for this file type
            analyzer = get_analyzer(language)
            if analyzer:
                # Use new language-specific analyzer for comprehensive detection
                # This provides better accuracy than generic pattern matching
                lang_vulns = analyzer.analyze(content, str(file_path))
                
                # Convert to Scanner Vulnerability format
                # Language analyzers may use different Vulnerability class
                for vuln in lang_vulns:
                    # Create Scanner-compatible Vulnerability object
                    vulnerabilities.append(Vulnerability(
                        cwe=vuln.cwe,  # CWE identifier
                        severity=vuln.severity,  # Severity level
                        title=vuln.title,  # Vulnerability title
                        description=vuln.description,  # Detailed description
                        file_path=vuln.file_path,  # File location
                        line_number=vuln.line_number,  # Line number
                        code_snippet=vuln.code_snippet,  # Code context
                        confidence=vuln.confidence,  # Detection confidence
                        category="security",  # Category classification
                        language=language  # Programming language
                    ))
            else:
                # Fall back to legacy detectors if no analyzer available
                # Split content into lines for pattern-based detection
                lines = content.split("\n")
                # Run each legacy detector
                for detector in self.detectors:
                    # Detect vulnerabilities using regex patterns
                    vulns = detector.detect(file_path, content, lines)
                    # Add vulnerabilities to the collection
                    vulnerabilities.extend(vulns)
        
        except Exception as e:
            # Skip files that can't be read (binary files, permission issues, etc.)
            # Silently ignore errors to continue scanning other files
            pass
        
        # Return all vulnerabilities found in this file
        return vulnerabilities


class VulnerabilityDetector:
    """
    Base class for vulnerability detectors
    
    This abstract base class defines the interface that all legacy detector
    classes must implement. Each detector focuses on a specific vulnerability type.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect vulnerabilities in file content
        
        Args:
            file_path: Path object for the file being analyzed
            content: Complete file content as a string
            lines: List of individual lines from the file
            
        Returns:
            List of Vulnerability objects detected
        """
        # Subclasses must implement this method
        raise NotImplementedError


class SQLInjectionDetector(VulnerabilityDetector):
    """
    Detects SQL injection vulnerabilities (CWE-89)
    
    SQL injection occurs when user input is concatenated directly into SQL
    queries without proper sanitization or parameterization. This can allow
    attackers to manipulate queries and access/modify unauthorized data.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect SQL injection patterns in code
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of SQL injection vulnerabilities found
        """
        # Initialize list to collect SQL injection vulnerabilities
        vulnerabilities = []
        
        # Python patterns that indicate SQL injection vulnerabilities
        py_patterns = [
            r'execute\s*\(\s*["\'].*%s.*["\'].*%',  # String formatting in execute() with %
            r'execute\s*\(\s*f["\'].*\{.*\}',  # F-string interpolation in execute()
            r'execute\s*\(\s*["\'].*\+.*\+',  # String concatenation in execute()
            r'cursor\.execute\s*\([^)]*\+',  # String concatenation with cursor.execute()
            r'\.raw\s*\([^)]*\+',  # String concatenation with .raw() (Django ORM)
        ]
        
        # JavaScript/TypeScript patterns for SQL injection
        js_patterns = [
            r'query\s*\([^)]*\+.*\+',  # String concatenation in query() method
            r'execute\s*\(`.*\$\{',  # Template literal with variable interpolation
            r'\.query\s*\(["\'].*\$\{',  # Query method with template literal interpolation
        ]
        
        # Combine all patterns into a single list for checking
        all_patterns = py_patterns + js_patterns
        
        # Iterate through each line of the file with line numbers (starting from 1)
        for i, line in enumerate(lines, 1):
            # Check each SQL injection pattern against the current line
            for pattern in all_patterns:
                # Perform case-insensitive regex search on the line
                if re.search(pattern, line, re.IGNORECASE):
                    # Create a Vulnerability object for the detected SQL injection
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-89",  # Common Weakness Enumeration for SQL Injection
                        severity="high",  # High severity due to potential data breach
                        title="SQL Injection",  # Short descriptive title
                        description="Potential SQL injection vulnerability detected. User input appears to be concatenated directly into SQL query.",  # Detailed explanation
                        file_path=str(file_path),  # Convert Path to string
                        line_number=i,  # Line number where vulnerability was found
                        code_snippet=line.strip(),  # Trimmed code snippet
                        confidence="medium",  # Medium confidence (pattern-based detection)
                        category="injection"  # Vulnerability category
                    ))
        
        # Return all SQL injection vulnerabilities found in this file
        return vulnerabilities


class XSSDetector(VulnerabilityDetector):
    """
    Detects Cross-Site Scripting vulnerabilities (CWE-79)
    
    XSS vulnerabilities occur when user input is rendered in web pages without
    proper sanitization, allowing attackers to inject malicious scripts that
    execute in victims' browsers.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect XSS vulnerability patterns in code
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of XSS vulnerabilities found
        """
        # Initialize list to store detected XSS vulnerabilities
        vulnerabilities = []
        
        # Regex patterns that commonly indicate XSS vulnerabilities
        patterns = [
            r'innerHTML\s*=',  # Direct assignment to innerHTML (JavaScript)
            r'document\.write\s*\(',  # Using document.write() which can inject HTML
            r'dangerouslySetInnerHTML',  # React's dangerous HTML rendering prop
            r'\.html\s*\([^)]*\+',  # jQuery's .html() with concatenation
            r'<script>.*\{.*\}.*</script>',  # Script tags with variable interpolation
        ]
        
        # Iterate through each line with line numbers starting from 1
        for i, line in enumerate(lines, 1):
            # Check each XSS pattern against the current line
            for pattern in patterns:
                # Perform case-insensitive regex search
                if re.search(pattern, line, re.IGNORECASE):
                    # Create Vulnerability object for detected XSS
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-79",  # CWE identifier for XSS
                        severity="high",  # High severity due to potential account compromise
                        title="Cross-Site Scripting (XSS)",  # Vulnerability title
                        description="Potential XSS vulnerability. User input may be rendered without proper sanitization.",  # Detailed description
                        file_path=str(file_path),  # File location as string
                        line_number=i,  # Line number of vulnerability
                        code_snippet=line.strip(),  # Trimmed code snippet
                        confidence="medium",  # Medium confidence for pattern matching
                        category="injection"  # Category classification
                    ))
        
        # Return all XSS vulnerabilities found
        return vulnerabilities


class SecretsDetector(VulnerabilityDetector):
    """
    Detects hardcoded secrets and credentials (CWE-798)
    
    Hardcoding secrets in source code is a critical security vulnerability as
    it exposes credentials to anyone with access to the code repository. Secrets
    should always be stored in environment variables or secure vaults.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect hardcoded secrets in code
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of hardcoded secret vulnerabilities found
        """
        # Initialize list to collect secret vulnerabilities
        vulnerabilities = []
        
        # Patterns for different types of secrets with descriptive labels
        patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', "password"),  # Password assignments
            (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']{10,}["\']', "API key"),  # API keys
            (r'(?i)(secret[_-]?key|secretkey)\s*=\s*["\'][^"\']{10,}["\']', "secret key"),  # Secret keys
            (r'(?i)(token)\s*=\s*["\'][^"\']{20,}["\']', "token"),  # Authentication tokens
            (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*=\s*["\'][A-Z0-9]{20}["\']', "AWS key"),  # AWS access keys
            (r'(?i)(private[_-]?key)\s*=\s*["\']-----BEGIN', "private key"),  # Private cryptographic keys
        ]
        
        # Iterate through each line with line numbers
        for i, line in enumerate(lines, 1):
            # Check each secret pattern
            for pattern, secret_type in patterns:
                # Search for the pattern in the line
                if re.search(pattern, line):
                    # Skip if it looks like a placeholder value (common in documentation/examples)
                    if any(placeholder in line.lower() for placeholder in 
                           ["example", "placeholder", "dummy", "test", "xxx", "***"]):
                        # Continue to next pattern if this is a placeholder
                        continue
                    
                    # Create Vulnerability object for the hardcoded secret
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-798",  # CWE for hardcoded credentials
                        severity="critical",  # Critical severity - immediate security risk
                        title="Hardcoded Credentials",  # Title
                        description=f"Hardcoded {secret_type} detected. Credentials should be stored in environment variables or secure vaults.",  # Description with secret type
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=self._redact_secret(line.strip()),  # Redacted code snippet
                        confidence="high",  # High confidence for this detection
                        category="secrets"  # Category
                    ))
        
        # Return all detected hardcoded secrets
        return vulnerabilities
    
    def _redact_secret(self, line: str) -> str:
        """
        Redact the actual secret value from the code snippet
        
        This prevents the actual secret from appearing in scan reports,
        which could create additional security risks.
        
        Args:
            line: Code line containing a secret
            
        Returns:
            Line with secret value replaced by "***REDACTED***"
        """
        # Replace any quoted string (the secret value) with redacted placeholder
        return re.sub(r'["\'][^"\']{3,}["\']', '"***REDACTED***"', line)


class PathTraversalDetector(VulnerabilityDetector):
    """
    Detects path traversal vulnerabilities (CWE-22)
    
    Path traversal vulnerabilities occur when applications use user input to
    construct file paths without proper validation, allowing attackers to access
    files outside the intended directory using sequences like "../".
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect path traversal vulnerability patterns
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of path traversal vulnerabilities found
        """
        # Initialize list for collecting path traversal vulnerabilities
        vulnerabilities = []
        
        # Regex patterns indicating potential path traversal vulnerabilities
        patterns = [
            r'open\s*\([^)]*\+',  # open() function with string concatenation
            r'readFile\s*\([^)]*\+',  # readFile() with concatenation (Node.js)
            r'readFileSync\s*\([^)]*\+',  # readFileSync() with concatenation (Node.js)
            r'File\s*\([^)]*\+',  # File constructor with concatenation (Java)
            r'\.read\s*\([^)]*\+',  # read() method with concatenation
        ]
        
        # Iterate through each line of code with line numbers
        for i, line in enumerate(lines, 1):
            # Check each path traversal pattern against the line
            for pattern in patterns:
                # Search for the pattern in the current line
                if re.search(pattern, line):
                    # Create Vulnerability object for detected path traversal
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-22",  # CWE identifier for path traversal
                        severity="high",  # High severity - can expose sensitive files
                        title="Path Traversal",  # Vulnerability title
                        description="Potential path traversal vulnerability. File paths should be validated to prevent directory traversal attacks.",  # Detailed description
                        file_path=str(file_path),  # Convert Path to string
                        line_number=i,  # Line number where found
                        code_snippet=line.strip(),  # Trimmed code snippet
                        confidence="medium",  # Medium confidence for pattern matching
                        category="injection"  # Vulnerability category
                    ))
        
        # Return all path traversal vulnerabilities found
        return vulnerabilities


class CommandInjectionDetector(VulnerabilityDetector):
    """
    Detects OS command injection vulnerabilities (CWE-78)
    
    Command injection occurs when user input is passed to system shell commands
    without proper sanitization, allowing attackers to execute arbitrary commands
    on the host system.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect command injection vulnerability patterns
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of command injection vulnerabilities found
        """
        # Initialize list for command injection vulnerabilities
        vulnerabilities = []
        
        # Regex patterns for dangerous command execution functions
        patterns = [
            r'os\.system\s*\([^)]*\+',  # Python os.system() with concatenation
            r'subprocess\.call\s*\([^)]*\+',  # Python subprocess.call() with concatenation
            r'exec\s*\([^)]*\+',  # exec() function with concatenation
            r'eval\s*\([^)]*\+',  # eval() function with concatenation (also code injection)
            r'shell_exec\s*\([^)]*\+',  # PHP shell_exec() with concatenation
            r'system\s*\([^)]*\$',  # system() call with variables
        ]
        
        # Iterate through each line with line numbers
        for i, line in enumerate(lines, 1):
            # Check each command injection pattern
            for pattern in patterns:
                # Search for pattern in current line
                if re.search(pattern, line):
                    # Create Vulnerability object for command injection
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-78",  # CWE identifier for OS command injection
                        severity="critical",  # Critical severity - allows system compromise
                        title="OS Command Injection",  # Vulnerability title
                        description="Potential command injection vulnerability. User input should never be passed directly to system commands.",  # Description
                        file_path=str(file_path),  # File path as string
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="high",  # High confidence detection
                        category="injection"  # Category
                    ))
        
        # Return all command injection vulnerabilities
        return vulnerabilities


class DeserializationDetector(VulnerabilityDetector):
    """
    Detects unsafe deserialization (CWE-502)
    
    Unsafe deserialization vulnerabilities occur when applications deserialize
    untrusted data without validation. This can lead to remote code execution,
    denial of service, or other attacks.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect unsafe deserialization patterns
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of unsafe deserialization vulnerabilities found
        """
        # Initialize vulnerabilities list
        vulnerabilities = []
        
        # Patterns for unsafe deserialization functions
        patterns = [
            r'pickle\.loads?\s*\(',  # Python pickle.load/loads (unsafe)
            r'yaml\.load\s*\([^,)]*\)',  # YAML load without SafeLoader
            r'unserialize\s*\(',  # PHP unserialize() function
            r'JSON\.parse\s*\([^)]*\+',  # JSON.parse with concatenation
        ]
        
        # Iterate through code lines with line numbers
        for i, line in enumerate(lines, 1):
            # Check each deserialization pattern
            for pattern in patterns:
                # Search for pattern in the line
                if re.search(pattern, line):
                    # Create Vulnerability for unsafe deserialization
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-502",  # CWE for deserialization of untrusted data
                        severity="high",  # High severity - can lead to RCE
                        title="Unsafe Deserialization",  # Title
                        description="Unsafe deserialization detected. Deserializing untrusted data can lead to remote code execution.",  # Description
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="medium",  # Medium confidence
                        category="deserialization"  # Category
                    ))
        
        # Return detected vulnerabilities
        return vulnerabilities


class WeakCryptoDetector(VulnerabilityDetector):
    """
    Detects weak cryptographic algorithms (CWE-327)
    
    Using weak or broken cryptographic algorithms like MD5 or SHA-1 can
    compromise the security of encrypted data. Modern applications should
    use SHA-256 or stronger algorithms.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect usage of weak cryptographic algorithms
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of weak cryptography vulnerabilities found
        """
        # Initialize list for weak crypto vulnerabilities
        vulnerabilities = []
        
        # Patterns for weak cryptographic algorithms with algorithm names
        patterns = [
            (r'\.md5\s*\(', "MD5"),  # MD5 hash (cryptographically broken)
            (r'\.sha1\s*\(', "SHA-1"),  # SHA-1 hash (deprecated)
            (r'hashlib\.md5', "MD5"),  # Python hashlib MD5
            (r'hashlib\.sha1', "SHA-1"),  # Python hashlib SHA-1
            (r'DES\s*\(', "DES"),  # DES encryption (too weak)
            (r'Cipher\.MODE_ECB', "ECB mode"),  # ECB mode (not secure)
        ]
        
        # Iterate through lines with line numbers
        for i, line in enumerate(lines, 1):
            # Check each weak crypto pattern
            for pattern, algo in patterns:
                # Case-insensitive search for the pattern
                if re.search(pattern, line, re.IGNORECASE):
                    # Create Vulnerability for weak cryptography
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-327",  # CWE for use of broken crypto
                        severity="medium",  # Medium severity - depends on usage
                        title="Weak Cryptographic Algorithm",  # Title
                        description=f"Weak cryptographic algorithm detected: {algo}. Use SHA-256 or stronger algorithms.",  # Description with algorithm name
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="high",  # High confidence for this detection
                        category="cryptography"  # Category
                    ))
        
        # Return all weak crypto vulnerabilities
        return vulnerabilities


class XXEDetector(VulnerabilityDetector):
    """
    Detects XML External Entity vulnerabilities (CWE-611)
    
    XXE vulnerabilities occur when XML parsers process external entity references
    without proper configuration, potentially allowing attackers to read local files,
    perform SSRF attacks, or cause denial of service.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect XML External Entity (XXE) vulnerability patterns
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of XXE vulnerabilities found
        """
        # Initialize vulnerabilities list
        vulnerabilities = []
        
        # Patterns indicating XML parsing that may be vulnerable to XXE
        patterns = [
            r'parse\s*\([^)]*xml',  # Generic parse function with xml
            r'XMLParser\s*\(',  # XMLParser constructor
            r'etree\.parse\s*\(',  # ElementTree parse method
            r'ElementTree\.parse\s*\(',  # ElementTree.parse
        ]
        
        # Iterate through lines with line numbers
        for i, line in enumerate(lines, 1):
            # Check each XXE-related pattern
            for pattern in patterns:
                # Case-insensitive search for XML parsing
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if safe parsing is used (XXE protection enabled)
                    if "resolve_entities=False" in line or "no_network=True" in line:
                        # Skip this line - it has XXE protection
                        continue
                    
                    # Create Vulnerability for potential XXE
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-611",  # CWE for XML External Entity injection
                        severity="medium",  # Medium severity - requires XML input
                        title="XML External Entity (XXE)",  # Title
                        description="Potential XXE vulnerability. XML parsers should disable external entity resolution.",  # Description
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="low",  # Low confidence - may have other protections
                        category="injection"  # Category
                    ))
        
        # Return XXE vulnerabilities found
        return vulnerabilities


class SSRFDetector(VulnerabilityDetector):
    """
    Detects Server-Side Request Forgery (CWE-918)
    
    SSRF vulnerabilities allow attackers to make the server send requests to
    arbitrary URLs, potentially accessing internal services, cloud metadata
    endpoints, or performing port scanning.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect Server-Side Request Forgery (SSRF) patterns
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of SSRF vulnerabilities found
        """
        # Initialize vulnerabilities list
        vulnerabilities = []
        
        # Patterns for HTTP request functions with user input
        patterns = [
            r'requests\.get\s*\([^)]*\+',  # Python requests.get with concatenation
            r'requests\.post\s*\([^)]*\+',  # Python requests.post with concatenation
            r'fetch\s*\([^)]*\+',  # JavaScript fetch with concatenation
            r'urllib\.request\.urlopen\s*\([^)]*\+',  # Python urllib with concatenation
            r'http\.get\s*\([^)]*\+',  # HTTP get with concatenation
        ]
        
        # Iterate through lines with line numbers
        for i, line in enumerate(lines, 1):
            # Check each SSRF pattern
            for pattern in patterns:
                # Search for pattern in line
                if re.search(pattern, line):
                    # Create Vulnerability for SSRF
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-918",  # CWE for Server-Side Request Forgery
                        severity="high",  # High severity - can access internal resources
                        title="Server-Side Request Forgery (SSRF)",  # Title
                        description="Potential SSRF vulnerability. URLs should be validated to prevent requests to internal resources.",  # Description
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="medium",  # Medium confidence
                        category="injection"  # Category
                    ))
        
        # Return SSRF vulnerabilities found
        return vulnerabilities


class PermissionDetector(VulnerabilityDetector):
    """
    Detects incorrect permission assignments (CWE-732)
    
    Overly permissive file permissions can allow unauthorized users to read,
    modify, or execute sensitive files. Files should use the principle of
    least privilege with minimal necessary permissions.
    """
    
    def detect(self, file_path: Path, content: str, lines: List[str]) -> List[Vulnerability]:
        """
        Detect incorrect file permission assignments
        
        Args:
            file_path: Path to file being scanned
            content: Complete file content
            lines: List of code lines
            
        Returns:
            List of permission vulnerabilities found
        """
        # Initialize vulnerabilities list
        vulnerabilities = []
        
        # Patterns for overly permissive file permissions with descriptions
        patterns = [
            (r'chmod\s*\(\s*[^,)]*\s*,\s*0?777', "777 (world-writable)"),  # chmod 777
            (r'os\.chmod\s*\([^,)]*,\s*0o777', "777 (world-writable)"),  # Python os.chmod 777
            (r'umask\s*\(\s*0+\s*\)', "000 (no restrictions)"),  # umask 000
        ]
        
        # Iterate through lines with line numbers
        for i, line in enumerate(lines, 1):
            # Check each permission pattern
            for pattern, perm in patterns:
                # Search for overly permissive patterns
                if re.search(pattern, line):
                    # Create Vulnerability for incorrect permissions
                    vulnerabilities.append(Vulnerability(
                        cwe="CWE-732",  # CWE for incorrect permission assignment
                        severity="medium",  # Medium severity - depends on file type
                        title="Incorrect Permission Assignment",  # Title
                        description=f"Overly permissive file permissions: {perm}. Files should use restrictive permissions.",  # Description with permission details
                        file_path=str(file_path),  # File path
                        line_number=i,  # Line number
                        code_snippet=line.strip(),  # Code snippet
                        confidence="high",  # High confidence - clear pattern
                        category="permissions"  # Category
                    ))
        
        # Return permission vulnerabilities found
        return vulnerabilities

