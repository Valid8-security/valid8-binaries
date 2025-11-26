#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Incremental Scanning Cache
Caches scan results to only rescan changed files
"""
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ScanCache:
    """Manages caching of scan results for incremental scanning"""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir:
            self.cache_dir = cache_dir
        else:
            self.cache_dir = Path.home() / ".parry" / "cache"
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "scan_cache.json"
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()
    
    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Error loading cache: {e}")
                return {}
        return {}
    
    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def get_file_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of file content"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""
    
    def is_file_changed(self, file_path: Path) -> bool:
        """Check if file has changed since last scan"""
        file_key = str(file_path.absolute())
        current_hash = self.get_file_hash(file_path)
        
        if file_key not in self.cache:
            return True
        
        cached_hash = self.cache[file_key].get('hash', '')
        return current_hash != cached_hash
    
    def get_cached_results(self, file_path: Path) -> Optional[List[Dict[str, Any]]]:
        """Get cached scan results for a file if unchanged"""
        if self.is_file_changed(file_path):
            return None
        
        file_key = str(file_path.absolute())
        if file_key in self.cache:
            return self.cache[file_key].get('results', [])
        
        return None
    
    def cache_results(self, file_path: Path, results: List[Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None):
        """Cache scan results for a file"""
        file_key = str(file_path.absolute())
        file_hash = self.get_file_hash(file_path)
        
        self.cache[file_key] = {
            'hash': file_hash,
            'results': results,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        }
    
    def get_changed_files(self, files: List[Path]) -> tuple[List[Path], List[Path]]:
        """
        Split files into changed and unchanged
        Returns: (changed_files, unchanged_files)
        """
        changed = []
        unchanged = []
        
        for file_path in files:
            if self.is_file_changed(file_path):
                changed.append(file_path)
            else:
                unchanged.append(file_path)
        
        return changed, unchanged
    
    def invalidate_file(self, file_path: Path):
        """Remove a file from cache"""
        file_key = str(file_path.absolute())
        if file_key in self.cache:
            del self.cache[file_key]
    
    def invalidate_all(self):
        """Clear entire cache"""
        self.cache = {}
        self._save_cache()
        logger.info("Cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_files = len(self.cache)
        total_size = 0
        oldest = None
        newest = None
        
        for entry in self.cache.values():
            timestamp = entry.get('timestamp')
            if timestamp:
                if not oldest or timestamp < oldest:
                    oldest = timestamp
                if not newest or timestamp > newest:
                    newest = timestamp
        
        try:
            total_size = self.cache_file.stat().st_size
        except:
            pass
        
        return {
            'total_files': total_files,
            'cache_size_bytes': total_size,
            'cache_size_mb': round(total_size / 1024 / 1024, 2),
            'oldest_entry': oldest,
            'newest_entry': newest
        }
    
    def prune_old_entries(self, days: int = 30):
        """Remove cache entries older than specified days"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        to_remove = []
        
        for file_key, entry in self.cache.items():
            timestamp_str = entry.get('timestamp')
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                    if timestamp < cutoff:
                        to_remove.append(file_key)
                except:
                    pass
        
        for key in to_remove:
            del self.cache[key]
        
        if to_remove:
            self._save_cache()
            logger.info(f"Pruned {len(to_remove)} old cache entries")
    
    def save(self):
        """Explicitly save cache to disk"""
        self._save_cache()


class ProjectCache:
    """Manages project-level caching including git integration"""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.cache_dir = project_path / ".parry" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.scan_cache = ScanCache(self.cache_dir)
    
    def get_git_changed_files(self) -> Set[Path]:
        """Get files changed in git (uncommitted + recently committed)"""
        import subprocess
        
        changed_files = set()
        
        try:
            # Get uncommitted changes
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD'],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        file_path = self.project_path / line
                        if file_path.exists():
                            changed_files.add(file_path)
            
            # Get untracked files
            result = subprocess.run(
                ['git', 'ls-files', '--others', '--exclude-standard'],
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        file_path = self.project_path / line
                        if file_path.exists():
                            changed_files.add(file_path)
        
        except Exception as e:
            logger.warning(f"Could not get git changed files: {e}")
        
        return changed_files
    
    def get_incremental_scan_plan(self, all_files: List[Path]) -> Dict[str, Any]:
        """
        Create an incremental scan plan
        Returns which files to scan and which to use from cache
        """
        git_changed = self.get_git_changed_files()
        changed, unchanged = self.scan_cache.get_changed_files(all_files)
        
        # Files to scan: either changed content or git changed
        to_scan = []
        use_cache = []
        
        for file_path in all_files:
            if file_path in changed or file_path in git_changed:
                to_scan.append(file_path)
            else:
                use_cache.append(file_path)
        
        return {
            'total_files': len(all_files),
            'to_scan': to_scan,
            'use_cache': use_cache,
            'scan_count': len(to_scan),
            'cache_count': len(use_cache),
            'cache_hit_rate': len(use_cache) / len(all_files) if all_files else 0
        }


