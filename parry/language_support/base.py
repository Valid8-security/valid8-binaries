# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Base class for language-specific analyzers

This module defines the abstract base class and data structures for all language-specific
security analyzers in Parry. It provides:

- Vulnerability dataclass: Standardized representation of security findings
  (CWE, severity, title, description, location, code snippet, confidence)

- LanguageAnalyzer ABC: Abstract base class enforcing common interface for all analyzers
  * analyze(): Main entry point for code analysis
  * get_supported_cwes(): Returns list of CWE types the analyzer can detect
  * parse_ast(): Optional AST parsing (language-specific)
  * detect_*() methods: Specific vulnerability detection methods

Supported Detection Methods:
- detect_command_injection() - CWE-78: Command injection
- detect_sql_injection() - CWE-89: SQL injection
- detect_xss() - CWE-79: Cross-site scripting
- detect_path_traversal() - CWE-22: Path traversal
- detect_weak_crypto() - CWE-327: Weak cryptography
- detect_hardcoded_secrets() - CWE-798: Hardcoded credentials
- detect_unsafe_deserialization() - CWE-502: Unsafe deserialization
- detect_xxe() - CWE-611: XML External Entity

Concrete Implementations:
- PythonAnalyzer (python_analyzer.py)
- JavaScriptAnalyzer (javascript_analyzer.py)
- JavaAnalyzer (java_analyzer.py)
- GoAnalyzer (go_analyzer.py)
- RubyAnalyzer (ruby_analyzer.py)
- RustAnalyzer (rust_analyzer.py)
- PHPAnalyzer (php_analyzer.py)
- CppAnalyzer (cpp_analyzer.py)

Each analyzer inherits from this base class and implements language-specific detection logic.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    cwe: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: str = "high"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'cwe': self.cwe,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'confidence': self.confidence,
        }


class LanguageAnalyzer(ABC):
    """Base class for language-specific security analyzers."""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.language = "unknown"
    
    @abstractmethod
    def analyze(self, code: str, filepath: str) -> List[Vulnerability]:
        """
        Analyze code for security vulnerabilities.
        
        Args:
            code: Source code to analyze
            filepath: Path to the source file
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    @abstractmethod
    def get_supported_cwes(self) -> List[str]:
        """Get list of CWE types this analyzer supports."""
        pass
    
    def parse_ast(self, code: str) -> Any:
        """
        Parse code into Abstract Syntax Tree.
        Override in language-specific analyzers.
        """
        return None
    
    def detect_command_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect command injection vulnerabilities (CWE-78)."""
        return []
    
    def detect_sql_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SQL injection vulnerabilities (CWE-89)."""
        return []
    
    def detect_xss(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XSS vulnerabilities (CWE-79)."""
        return []
    
    def detect_path_traversal(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect path traversal vulnerabilities (CWE-22)."""
        return []
    
    def detect_weak_crypto(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect weak cryptography (CWE-327)."""
        return []
    
    def detect_hardcoded_secrets(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect hardcoded credentials (CWE-798)."""
        return []
    
    def detect_unsafe_deserialization(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect unsafe deserialization (CWE-502)."""
        return []
    
    def detect_xxe(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect XXE vulnerabilities (CWE-611)."""
        return []
    
    def detect_ssrf(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect SSRF vulnerabilities (CWE-918)."""
        return []
    
    def detect_ldap_injection(self, code: str, filepath: str) -> List[Vulnerability]:
        """Detect LDAP injection (CWE-90)."""
        return []
    
    def _create_vulnerability(
        self,
        cwe: str,
        severity: str,
        title: str,
        description: str,
        code: str,
        filepath: str,
        line_number: int,
        confidence: str = "high"
    ) -> Vulnerability:
        """Helper to create a vulnerability object."""
        lines = code.split('\n')
        snippet = lines[line_number - 1] if line_number <= len(lines) else ""
        
        return Vulnerability(
            cwe=cwe,
            severity=severity,
            title=title,
            description=description,
            file_path=filepath,
            line_number=line_number,
            code_snippet=snippet.strip(),
            confidence=confidence
        )


