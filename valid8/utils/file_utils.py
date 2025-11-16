"""
File Utilities - Common file operations
"""
import os
import hashlib
from pathlib import Path
from typing import List, Set, Optional


def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
    """Calculate file hash"""
    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def get_file_size_mb(file_path: Path) -> float:
    """Get file size in MB"""
    return file_path.stat().st_size / (1024 * 1024)


def should_exclude_path(path: str, exclude_patterns: List[str]) -> bool:
    """Check if path should be excluded based on patterns"""
    from fnmatch import fnmatch

    # Normalize path separators
    path = path.replace('\\', '/')

    for pattern in exclude_patterns:
        # Handle directory patterns
        if pattern.endswith('/**') or pattern.endswith('**'):
            pattern = pattern.rstrip('/*')
            if path.startswith(pattern) or pattern in path:
                return True
        # Handle file patterns
        elif fnmatch(path, pattern) or fnmatch(Path(path).name, pattern):
            return True

    return False


def discover_files(root_path: Path,
                  include_extensions: Optional[Set[str]] = None,
                  exclude_patterns: Optional[List[str]] = None,
                  max_file_size_mb: Optional[float] = None) -> List[Path]:
    """
    Discover files recursively with filtering

    Args:
        root_path: Root directory to search
        include_extensions: File extensions to include (e.g., {'.py', '.js'})
        exclude_patterns: Patterns to exclude (glob-style)
        max_file_size_mb: Maximum file size in MB

    Returns:
        List of matching file paths
    """
    if not root_path.exists():
        return []

    files = []
    exclude_patterns = exclude_patterns or []
    include_extensions = include_extensions or {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go'}

    for root, dirs, filenames in os.walk(root_path):
        # Filter directories
        dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d), exclude_patterns)]

        for filename in filenames:
            file_path = Path(root) / filename

            # Check if file should be excluded
            if should_exclude_path(str(file_path), exclude_patterns):
                continue

            # Check file extension
            if file_path.suffix not in include_extensions:
                continue

            # Check file size
            if max_file_size_mb and get_file_size_mb(file_path) > max_file_size_mb:
                continue

            files.append(file_path)

    return files


def read_file_safe(file_path: Path, encoding: str = 'utf-8',
                  max_size_mb: float = 10.0) -> Optional[str]:
    """Safely read file content with size limits"""
    try:
        if get_file_size_mb(file_path) > max_size_mb:
            return None

        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()

    except (OSError, UnicodeDecodeError):
        return None


def get_file_language(file_path: Path) -> str:
    """Determine programming language from file extension"""
    extension_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.scala': 'scala',
        '.kt': 'kotlin',
        '.swift': 'swift',
        '.m': 'objective-c',
        '.pl': 'perl',
        '.lua': 'lua',
        '.r': 'r',
        '.sh': 'bash',
        '.sql': 'sql',
        '.html': 'html',
        '.xml': 'xml',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.toml': 'toml',
        '.ini': 'ini',
        '.cfg': 'config',
        '.conf': 'config'
    }

    return extension_map.get(file_path.suffix.lower(), 'unknown')


def get_project_root(start_path: Path) -> Path:
    """Find project root by looking for common markers"""
    current = start_path.resolve()

    # Go up until we find project markers
    markers = ['.git', 'requirements.txt', 'package.json', 'pom.xml',
              'build.gradle', 'Cargo.toml', 'go.mod', '.valid8']

    while current.parent != current:  # Stop at filesystem root
        if any((current / marker).exists() for marker in markers):
            return current
        current = current.parent

    # Fallback to start path
    return start_path


def ensure_directory(path: Path) -> None:
    """Ensure directory exists"""
    path.mkdir(parents=True, exist_ok=True)
