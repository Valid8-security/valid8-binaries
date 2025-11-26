#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Incremental Scanning - Git-based Changed File Detection

Scans only files that have changed since last scan, providing 10-100x speedup
for re-scans. Uses git diff to identify changed files.
"""

import subprocess
from pathlib import Path
from typing import List, Optional, Set
import hashlib


class IncrementalScanner:
    """Git-based incremental scanning for fast re-scans"""
    
    @staticmethod
    def is_git_repo(path: Path) -> bool:
        """Check if path is a git repository"""
        return (path / '.git').exists() or IncrementalScanner._find_git_root(path) is not None
    
    @staticmethod
    def _find_git_root(path: Path) -> Optional[Path]:
        """Find git root by walking up the directory tree"""
        current = path.resolve()
        while current != current.parent:
            if (current / '.git').exists():
                return current
            current = current.parent
        return None
    
    @staticmethod
    def get_changed_files(
        repo_path: Path,
        base_ref: str = "HEAD~1",
        include_untracked: bool = True
    ) -> List[Path]:
        """
        Get files changed since base_ref.
        
        Args:
            repo_path: Repository root path
            base_ref: Base reference (default: HEAD~1 for last commit)
            include_untracked: Include untracked files
            
        Returns:
            List of changed file paths
        """
        git_root = IncrementalScanner._find_git_root(repo_path) or repo_path
        
        try:
            # Get tracked changed files
            result = subprocess.run(
                ['git', 'diff', '--name-only', f'{base_ref}..HEAD'],
                cwd=git_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            changed_files = set()
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        file_path = git_root / line
                        if file_path.exists() and file_path.is_file():
                            changed_files.add(file_path)
            
            # Get staged files
            result_staged = subprocess.run(
                ['git', 'diff', '--cached', '--name-only'],
                cwd=git_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result_staged.returncode == 0:
                for line in result_staged.stdout.strip().split('\n'):
                    if line:
                        file_path = git_root / line
                        if file_path.exists() and file_path.is_file():
                            changed_files.add(file_path)
            
            # Get untracked files if requested
            if include_untracked:
                result_untracked = subprocess.run(
                    ['git', 'ls-files', '--others', '--exclude-standard'],
                    cwd=git_root,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result_untracked.returncode == 0:
                    for line in result_untracked.stdout.strip().split('\n'):
                        if line:
                            file_path = git_root / line
                            if file_path.exists() and file_path.is_file():
                                changed_files.add(file_path)
            
            return list(changed_files)
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return []
    
    @staticmethod
    def get_modified_files_from_status(repo_path: Path) -> List[Path]:
        """
        Get modified files from git status (working tree changes).
        Faster alternative that doesn't compare to HEAD.
        """
        git_root = IncrementalScanner._find_git_root(repo_path) or repo_path
        
        try:
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=git_root,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            changed_files = set()
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and len(line) > 3:
                        # Format: " M file.py" or "?? file.py"
                        status = line[:2]
                        filepath = line[3:]
                        
                        # Include modified, added, untracked files
                        if status.strip() in ['M', 'A', 'AM', '??', 'MM']:
                            file_path = git_root / filepath
                            if file_path.exists() and file_path.is_file():
                                changed_files.add(file_path)
            
            return list(changed_files)
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return []
    
    @staticmethod
    def filter_changed_files(
        all_files: List[Path],
        repo_path: Path,
        base_ref: str = "HEAD~1"
    ) -> List[Path]:
        """
        Filter file list to only include changed files.
        
        Args:
            all_files: List of all files to potentially scan
            repo_path: Repository root
            base_ref: Git reference to compare against
            
        Returns:
            Filtered list containing only changed files
        """
        if not IncrementalScanner.is_git_repo(repo_path):
            return all_files  # Not a git repo, return all files
        
        changed_files = IncrementalScanner.get_changed_files(repo_path, base_ref)
        
        if not changed_files:
            # No changes detected, but might be new repo or error
            # Fall back to checking git status
            changed_files = IncrementalScanner.get_modified_files_from_status(repo_path)
        
        if not changed_files:
            # Still no changes, return all files (might be first scan)
            return all_files
        
        # Convert to set for O(1) lookup
        changed_set = set(f.resolve() for f in changed_files)
        
        # Filter all_files to only those in changed_set
        filtered = [f for f in all_files if f.resolve() in changed_set]
        
        return filtered if filtered else all_files
    
    @staticmethod
    def get_file_hash(filepath: Path) -> str:
        """Get hash of file contents for change detection"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (IOError, OSError):
            return ""
    
    @staticmethod
    def compare_with_last_scan(
        files: List[Path],
        cache_dir: Path
    ) -> List[Path]:
        """
        Compare files with last scan using hash-based change detection.
        Alternative to git-based detection for non-git repos.
        
        Args:
            files: List of files to check
            cache_dir: Directory containing scan cache
            
        Returns:
            List of files that have changed since last scan
        """
        cache_file = cache_dir / 'file_hashes.cache'
        
        # Load previous hashes
        previous_hashes = {}
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            path, hash_val = line.strip().split(':', 1)
                            previous_hashes[path] = hash_val
            except (IOError, OSError):
                pass
        
        # Find changed files
        changed_files = []
        current_hashes = {}
        
        for filepath in files:
            file_str = str(filepath)
            current_hash = IncrementalScanner.get_file_hash(filepath)
            current_hashes[file_str] = current_hash
            
            # File is changed if hash differs or file is new
            if file_str not in previous_hashes or previous_hashes[file_str] != current_hash:
                changed_files.append(filepath)
        
        # Save current hashes for next scan
        cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                for path, hash_val in current_hashes.items():
                    f.write(f"{path}:{hash_val}\n")
        except (IOError, OSError):
            pass
        
        return changed_files if changed_files else files

