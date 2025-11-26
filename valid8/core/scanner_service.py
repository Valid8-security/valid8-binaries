#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Scanner Service - Core scanning orchestration
"""
import os
import uuid
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..interfaces.scanner import IScanner, ScanResult, IDetector
from .config_manager import config_manager
from .dependency_container import get_service


class ModularScanner(IScanner):
    """Modular scanner that orchestrates different scanning components"""

    def __init__(self):
        self.config = config_manager
        self.detectors: List[IDetector] = []
        self._load_detectors()

    def _load_detectors(self) -> None:
        """Load available detectors"""
        # This will be enhanced with plugin system
        try:
            from ..detectors import get_legacy_detectors
            self.detectors.extend(get_legacy_detectors())
        except ImportError:
            pass

    def scan(self, target: Path, **kwargs) -> ScanResult:
        """Perform comprehensive vulnerability scan"""
        scan_id = str(uuid.uuid4())
        start_time = time.time()

        mode = kwargs.get('mode', self.config.get('default_scan_mode', 'fast'))
        exclude_patterns = kwargs.get('exclude_patterns', [])

        # Discover files to scan
        files_to_scan = self._discover_files(target, exclude_patterns)

        # Perform scanning
        vulnerabilities = []
        files_scanned = 0

        for file_path in files_to_scan:
            try:
                file_vulns = self._scan_file(file_path, mode, **kwargs)
                vulnerabilities.extend(file_vulns)
                files_scanned += 1
            except Exception as e:
                # Log error but continue scanning
                print(f"Error scanning {file_path}: {e}")
                continue

        scan_time = time.time() - start_time

        return ScanResult(
            scan_id=scan_id,
            target=str(target),
            vulnerabilities=vulnerabilities,
            files_scanned=files_scanned,
            scan_time=scan_time,
            mode=mode,
            metadata={
                'scanner_version': '2.0.0',
                'total_files_discovered': len(files_to_scan)
            }
        )

    def _discover_files(self, target: Path, exclude_patterns: List[str]) -> List[Path]:
        """Discover files to scan"""
        if target.is_file():
            return [target]

        files = []
        exclude_patterns = exclude_patterns or self._get_default_excludes()

        for root, dirs, files_in_dir in os.walk(target):
            # Apply directory exclusions
            dirs[:] = [d for d in dirs if not self._should_exclude(d, exclude_patterns)]

            for file in files_in_dir:
                file_path = Path(root) / file
                if not self._should_exclude(str(file_path), exclude_patterns):
                    # Check if we have analyzers for this file type
                    if self._can_analyze_file(file_path):
                        files.append(file_path)

        return files

    def _scan_file(self, file_path: Path, mode: str, **kwargs) -> List[Dict[str, Any]]:
        """Scan individual file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            vulnerabilities = []

            # Use language-specific analyzers first
            lang_vulns = self._scan_with_analyzers(file_path, content, mode)
            vulnerabilities.extend(lang_vulns)

            # Use general detectors
            detector_vulns = self._scan_with_detectors(file_path, content, mode)
            vulnerabilities.extend(detector_vulns)

            # Apply AI validation if requested
            if kwargs.get('validate', False) and mode in ['hybrid', 'deep']:
                vulnerabilities = self._apply_ai_validation(vulnerabilities, file_path, content)

            return vulnerabilities

        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []

    def _scan_with_analyzers(self, file_path: Path, content: str, mode: str) -> List[Dict[str, Any]]:
        """Scan using language-specific analyzers"""
        # This will be implemented with the plugin system
        return []

    def _scan_with_detectors(self, file_path: Path, content: str, mode: str) -> List[Dict[str, Any]]:
        """Scan using general detectors"""
        vulnerabilities = []
        lines = content.split('\n')

        for detector in self.detectors:
            try:
                file_vulns = detector.detect(file_path, content, lines)
                vulnerabilities.extend(file_vulns)
            except Exception as e:
                print(f"Detector {detector.name} failed: {e}")
                continue

        return vulnerabilities

    def _apply_ai_validation(self, vulnerabilities: List[Dict[str, Any]],
                           file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Apply AI validation to filter false positives"""
        try:
            from ..ai_true_positive_validator import AITruePositiveValidator
            validator = AITruePositiveValidator()

            validated = []
            for vuln in vulnerabilities:
                result = validator.validate_vulnerability(vuln)
                if result.is_true_positive:
                    vuln['ai_confidence'] = result.confidence_score
                    vuln['ai_reason'] = result.validation_reason
                    validated.append(vuln)

            return validated

        except ImportError:
            return vulnerabilities

    def _can_analyze_file(self, file_path: Path) -> bool:
        """Check if file can be analyzed"""
        # Check file size
        max_size = self.config.get('max_file_size', 10 * 1024 * 1024)
        if file_path.stat().st_size > max_size:
            return False

        # Check file extension
        supported_extensions = self._get_supported_extensions()
        return file_path.suffix in supported_extensions

    def _get_supported_extensions(self) -> List[str]:
        """Get supported file extensions"""
        return ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go']

    def _get_default_excludes(self) -> List[str]:
        """Get default exclusion patterns"""
        return [
            '.git/**', '.svn/**', '__pycache__/**', 'node_modules/**',
            '*.pyc', '*.pyo', '*.class', 'target/**', 'build/**'
        ]

    def _should_exclude(self, path: str, patterns: List[str]) -> bool:
        """Check if path should be excluded"""
        from fnmatch import fnmatch
        for pattern in patterns:
            if fnmatch(path, pattern):
                return True
        return False

    def supports_mode(self, mode: str) -> bool:
        """Check if scanner supports given mode"""
        return mode in ['fast', 'hybrid', 'deep']

    def get_capabilities(self) -> Dict[str, Any]:
        """Return scanner capabilities"""
        return {
            'supported_modes': ['fast', 'hybrid', 'deep'],
            'supported_languages': ['python', 'javascript', 'typescript', 'java', 'cpp', 'csharp', 'php', 'ruby', 'go'],
            'ai_validation': True,
            'max_file_size': self.config.get('max_file_size'),
            'detectors_count': len(self.detectors)
        }


# Factory function
def create_scanner() -> IScanner:
    """Create scanner instance"""
    return ModularScanner()
