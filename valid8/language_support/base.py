#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Base class for language-specific analyzers.
"""

from abc import ABC, abstractmethod
from ..models import Vulnerability
from typing import List, Dict, Any


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


