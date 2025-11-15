"""
Global cache system for file analysis results
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional, Dict
from threading import Lock


class GlobalCache:
    """Global cache for storing analysis results"""

    def __init__(self):
        self.cache_dir = Path.home() / ".parry" / "global_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "global_cache.json"
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass  # Silently fail

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry.get('expires', 0) > time.time():
                    return entry['value']
                else:
                    # Expired, remove it
                    del self._cache[key]
                    self._save_cache()
        return None

    def set(self, key: str, value: Any, ttl: int = 3600):
        """Set value in cache with TTL"""
        with self._lock:
            self._cache[key] = {
                'value': value,
                'expires': time.time() + ttl
            }
            self._save_cache()

    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._save_cache()


def generate_file_fingerprint(file_path: Path) -> str:
    """
    Generate a fingerprint for a file based on its path, size, and modification time

    Args:
        file_path: Path to the file

    Returns:
        Fingerprint string
    """
    try:
        stat = file_path.stat()
        fingerprint_data = f"{file_path}:{stat.st_size}:{stat.st_mtime}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    except Exception:
        # Fallback to path-based fingerprint
        return hashlib.md5(str(file_path).encode()).hexdigest()


# Global cache instance
cache_system = GlobalCache()
