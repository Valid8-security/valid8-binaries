#!/usr/bin/env python3
"""
Caching system for Valid8 security scanner

Provides intelligent caching of analysis results to avoid re-scanning unchanged code.
Uses file modification times and content hashes for cache invalidation.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

from ..models import Vulnerability


@dataclass
class CacheEntry:
    """Cache entry for analysis results"""
    file_path: str
    file_hash: str
    modification_time: float
    analysis_time: float
    vulnerabilities: List[Dict[str, Any]]
    scanner_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry':
        return cls(
            file_path=data['file_path'],
            file_hash=data['file_hash'],
            modification_time=data['modification_time'],
            analysis_time=data['analysis_time'],
            vulnerabilities=data['vulnerabilities'],
            scanner_version=data.get('scanner_version', '1.0.0')
        )

    def is_valid(self, current_mtime: float, current_hash: str) -> bool:
        """Check if cache entry is still valid"""
        return (self.modification_time == current_mtime and
                self.file_hash == current_hash and
                self.scanner_version == "1.0.0")


class AnalysisCache:
    """Intelligent caching system for security analysis results"""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path.home() / '.valid8' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / 'analysis_cache.json'
        self._cache: Dict[str, CacheEntry] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    for file_path, entry_data in data.items():
                        self._cache[file_path] = CacheEntry.from_dict(entry_data)
            except (json.JSONDecodeError, KeyError):
                # Corrupted cache, start fresh
                self._cache = {}

    def _save_cache(self) -> None:
        """Save cache to disk"""
        try:
            data = {path: entry.to_dict() for path, entry in self._cache.items()}
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            # If we can't save cache, continue without it
            pass

    def get_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file contents"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (OSError, IOError):
            return ""

    def get_cached_result(self, file_path: Path) -> Optional[List[Vulnerability]]:
        """
        Get cached analysis result if valid

        Args:
            file_path: Path to the file to check

        Returns:
            List of vulnerabilities if cache is valid, None otherwise
        """
        if str(file_path) not in self._cache:
            return None

        entry = self._cache[str(file_path)]

        try:
            current_mtime = file_path.stat().st_mtime
            current_hash = self.get_file_hash(file_path)

            if entry.is_valid(current_mtime, current_hash):
                # Convert dict vulnerabilities back to Vulnerability objects
                vulnerabilities = []
                for vuln_dict in entry.vulnerabilities:
                    try:
                        vuln = Vulnerability(**vuln_dict)
                        vulnerabilities.append(vuln)
                    except Exception:
                        # Skip invalid cached vulnerabilities
                        continue
                return vulnerabilities
        except (OSError, IOError):
            # File no longer accessible
            pass

        return None

    def cache_result(self, file_path: Path, vulnerabilities: List[Vulnerability]) -> None:
        """
        Cache analysis result for future use

        Args:
            file_path: Path to the analyzed file
            vulnerabilities: List of vulnerabilities found
        """
        try:
            mtime = file_path.stat().st_mtime
            file_hash = self.get_file_hash(file_path)

            # Convert Vulnerability objects to dicts for JSON serialization
            vuln_dicts = []
            for vuln in vulnerabilities:
                try:
                    vuln_dicts.append({
                        'type': vuln.type,
                        'title': vuln.title,
                        'description': vuln.description,
                        'file_path': vuln.file_path,
                        'line_number': vuln.line_number,
                        'code_snippet': vuln.code_snippet,
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'cwe_id': getattr(vuln, 'cwe_id', None),
                        'owasp_id': getattr(vuln, 'owasp_id', None),
                        'recommendation': getattr(vuln, 'recommendation', ''),
                        'metadata': getattr(vuln, 'metadata', {})
                    })
                except Exception:
                    # Skip vulnerabilities that can't be serialized
                    continue

            entry = CacheEntry(
                file_path=str(file_path),
                file_hash=file_hash,
                modification_time=mtime,
                analysis_time=time.time(),
                vulnerabilities=vuln_dicts
            )

            self._cache[str(file_path)] = entry
            self._save_cache()

        except Exception:
            # If caching fails, continue without it
            pass

    def clear_cache(self) -> None:
        """Clear all cached results"""
        self._cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(self._cache)
        total_vulnerabilities = sum(len(entry.vulnerabilities) for entry in self._cache.values())

        if self._cache:
            avg_analysis_time = sum(entry.analysis_time for entry in self._cache.values()) / total_entries
        else:
            avg_analysis_time = 0

        return {
            'total_cached_files': total_entries,
            'total_cached_vulnerabilities': total_vulnerabilities,
            'average_analysis_time': avg_analysis_time,
            'cache_size_mb': self.cache_file.stat().st_size / (1024 * 1024) if self.cache_file.exists() else 0
        }

    def cleanup_expired_entries(self, max_age_days: int = 30) -> int:
        """
        Remove cache entries older than specified days

        Args:
            max_age_days: Maximum age in days for cache entries

        Returns:
            Number of entries removed
        """
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        expired_paths = []

        for path, entry in self._cache.items():
            if entry.analysis_time < cutoff_time:
                expired_paths.append(path)

        for path in expired_paths:
            del self._cache[path]

        if expired_paths:
            self._save_cache()

        return len(expired_paths)
