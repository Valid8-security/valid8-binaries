#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Scanner Interface - Core abstraction for vulnerability scanning
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pathlib import Path


class ScanResult:
    """Standardized scan result structure"""
    def __init__(self,
                 scan_id: str,
                 target: str,
                 vulnerabilities: List[Dict[str, Any]],
                 files_scanned: int,
                 scan_time: float,
                 mode: str,
                 metadata: Optional[Dict[str, Any]] = None):
        self.scan_id = scan_id
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.files_scanned = files_scanned
        self.scan_time = scan_time
        self.mode = mode
        self.metadata = metadata or {}


class IScanner(ABC):
    """Interface for vulnerability scanners"""

    @abstractmethod
    def scan(self, target: Path, **kwargs) -> ScanResult:
        """Perform vulnerability scan on target"""
        pass

    @abstractmethod
    def supports_mode(self, mode: str) -> bool:
        """Check if scanner supports given mode"""
        pass

    @abstractmethod
    def get_capabilities(self) -> Dict[str, Any]:
        """Return scanner capabilities and supported features"""
        pass


class IDetector(ABC):
    """Interface for vulnerability detectors"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name"""
        pass

    @property
    @abstractmethod
    def supported_languages(self) -> List[str]:
        """Languages this detector supports"""
        pass

    @abstractmethod
    def detect(self, file_path: Path, content: str, **kwargs) -> List[Dict[str, Any]]:
        """Detect vulnerabilities in file content"""
        pass

    @abstractmethod
    def get_supported_cwes(self) -> List[str]:
        """Return list of CWE IDs this detector can find"""
        pass


class IAnalyzer(ABC):
    """Interface for code analyzers (language-specific)"""

    @property
    @abstractmethod
    def language(self) -> str:
        """Programming language this analyzer handles"""
        pass

    @abstractmethod
    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze code and return vulnerabilities"""
        pass

    @abstractmethod
    def can_analyze(self, file_path: str) -> bool:
        """Check if this analyzer can handle the file"""
        pass

