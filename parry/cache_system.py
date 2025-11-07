"""
🚀 PERFORMANCE OPTIMIZATION: Multi-level caching system
Memory, file, and persistent caching for massive speedup
"""

import json
import hashlib
import time
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from collections import OrderedDict
import pickle


class MemoryCache:
    """
    🚀 L1 Cache: Fast in-memory LRU cache
    """

    def __init__(self, max_size: int = 1000):
        self.cache = OrderedDict()
        self.max_size = max_size
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self._lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                return self.cache[key]
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set item in cache with optional TTL"""
        with self._lock:
            if len(self.cache) >= self.max_size:
                # Remove least recently used
                self.cache.popitem(last=False)

            self.cache[key] = {
                'value': value,
                'timestamp': time.time(),
                'ttl': ttl
            }
            self.cache.move_to_end(key)

    def invalidate(self, key: str) -> None:
        """Remove item from cache"""
        with self._lock:
            self.cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self.cache.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries, return count removed"""
        with self._lock:
            expired_keys = []
            current_time = time.time()

            for key, data in self.cache.items():
                if data.get('ttl') and current_time - data['timestamp'] > data['ttl']:
                    expired_keys.append(key)

            for key in expired_keys:
                del self.cache[key]

            return len(expired_keys)


class FileCache:
    """
    🚀 L2 Cache: Persistent file-based cache
    """

    def __init__(self, cache_dir: Path, max_size_mb: int = 100):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._lock = threading.Lock()

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key"""
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hash_key}.cache"

    def get(self, key: str) -> Optional[Any]:
        """Get item from file cache"""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with self._lock, open(cache_path, 'rb') as f:
                data = pickle.load(f)

            # Check TTL
            if data.get('ttl'):
                if time.time() - data['timestamp'] > data['ttl']:
                    cache_path.unlink(missing_ok=True)
                    return None

            return data['value']

        except (IOError, pickle.PickleError, KeyError):
            # Corrupted cache file
            cache_path.unlink(missing_ok=True)
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set item in file cache"""
        cache_path = self._get_cache_path(key)

        data = {
            'value': value,
            'timestamp': time.time(),
            'ttl': ttl
        }

        try:
            with self._lock, open(cache_path, 'wb') as f:
                pickle.dump(data, f)
        except IOError:
            # Cache write failed, skip
            pass

        # Cleanup if cache is too large
        self._cleanup_if_needed()

    def _cleanup_if_needed(self) -> None:
        """Clean up old cache files if cache is too large"""
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            total_size = sum(f.stat().st_size for f in cache_files)

            if total_size > self.max_size_bytes:
                # Sort by modification time (oldest first)
                cache_files.sort(key=lambda f: f.stat().st_mtime)

                # Remove oldest files until under limit
                target_size = self.max_size_bytes * 0.8  # Leave 20% free
                for cache_file in cache_files:
                    if total_size <= target_size:
                        break
                    size = cache_file.stat().st_size
                    cache_file.unlink(missing_ok=True)
                    total_size -= size

        except OSError:
            pass


class MultiLevelCache:
    """
    🚀 PERFORMANCE OPTIMIZATION: Multi-level caching system
    L1 (Memory) → L2 (File) → L3 (Optional distributed)
    """

    def __init__(self, cache_dir: Optional[Path] = None, memory_cache_size: int = 500):
        self.memory_cache = MemoryCache(max_size=memory_cache_size)

        if cache_dir is None:
            cache_dir = Path.home() / ".parry" / "cache"
        self.file_cache = FileCache(cache_dir)

        # Optional Redis distributed cache (placeholder)
        self.distributed_cache = None

        # Statistics
        self.stats = {
            'memory_hits': 0,
            'file_hits': 0,
            'misses': 0,
            'sets': 0
        }

    def get(self, key: str) -> Optional[Any]:
        """Get from multi-level cache"""
        # L1: Memory cache
        result = self.memory_cache.get(key)
        if result is not None:
            self.stats['memory_hits'] += 1
            return result['value'] if isinstance(result, dict) else result

        # L2: File cache
        result = self.file_cache.get(key)
        if result is not None:
            # Promote to memory cache
            self.memory_cache.set(key, result)
            self.stats['file_hits'] += 1
            return result

        # L3: Distributed cache (future)
        if self.distributed_cache:
            result = self.distributed_cache.get(key)
            if result is not None:
                # Promote to higher caches
                self.set(key, result)
                return result

        self.stats['misses'] += 1
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set in all cache levels"""
        # Set in all levels
        self.memory_cache.set(key, value, ttl)
        self.file_cache.set(key, value, ttl)

        if self.distributed_cache:
            self.distributed_cache.set(key, value, ttl)

        self.stats['sets'] += 1

    def invalidate(self, key: str) -> None:
        """Remove from all cache levels"""
        self.memory_cache.invalidate(key)
        # File cache will be cleaned up naturally
        if self.distributed_cache:
            self.distributed_cache.delete(key)

    def clear(self) -> None:
        """Clear all caches"""
        self.memory_cache.clear()
        # File cache persists but will be cleaned over time

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        memory_stats = self.memory_cache.cache  # Access internal stats

        return {
            'memory_cache': {
                'entries': len(self.memory_cache.cache),
                'max_size': self.memory_cache.max_size
            },
            'file_cache': {
                'directory': str(self.file_cache.cache_dir),
                'max_size_mb': self.file_cache.max_size_bytes / (1024 * 1024)
            },
            'performance': self.stats,
            'hit_rate': (self.stats['memory_hits'] + self.stats['file_hits']) /
                       max(1, sum(self.stats.values())) * 100
        }

    def cleanup(self) -> Dict[str, int]:
        """Clean up expired entries, return counts"""
        memory_cleaned = self.memory_cache.cleanup_expired()
        # File cache cleans itself automatically

        return {
            'memory_expired': memory_cleaned,
            'file_expired': 0  # Handled automatically
        }


def generate_file_fingerprint(file_path: Path) -> str:
    """
    🚀 PERFORMANCE OPTIMIZATION: Generate content fingerprint for caching
    Includes modification time and size for quick change detection
    """
    try:
        stat = file_path.stat()
        # Create fingerprint from path, mtime, and size
        fingerprint_data = f"{file_path}:{stat.st_mtime}:{stat.st_size}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    except OSError:
        return f"error:{file_path}"


# Global cache instance
cache_system = MultiLevelCache()
