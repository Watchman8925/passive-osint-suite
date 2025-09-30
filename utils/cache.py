"""
Caching Layer for OSINT Suite
Cache API responses to reduce redundant calls and respect rate limits
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from utils.osint_utils import OSINTUtils


class CacheEntry:
    """Represents a cached item with metadata"""

    def __init__(self, key: str, data: Any, ttl_seconds: int = 3600):
        self.key = key
        self.data = data
        self.timestamp = datetime.now()
        self.ttl_seconds = ttl_seconds
        self.access_count = 0
        self.last_accessed = datetime.now()

    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return datetime.now() - self.timestamp > timedelta(seconds=self.ttl_seconds)

    def access(self):
        """Mark entry as accessed"""
        self.access_count += 1
        self.last_accessed = datetime.now()

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "key": self.key,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CacheEntry":
        """Create from dictionary"""
        entry = cls(key=data["key"], data=data["data"], ttl_seconds=data["ttl_seconds"])
        entry.timestamp = datetime.fromisoformat(data["timestamp"])
        entry.access_count = data.get("access_count", 0)
        entry.last_accessed = datetime.fromisoformat(
            data.get("last_accessed", data["timestamp"])
        )
        return entry


class OSINTCache:
    """Caching system for OSINT operations"""

    def __init__(self, cache_dir: Optional[str] = None, max_size: int = 1000):
        self.utils = OSINTUtils()
        self.cache_dir = cache_dir or os.path.join("output", "cache")
        self.max_size = max_size
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()

        # Default TTL values for different types of data
        self.default_ttl = {
            "ip_info": 3600,  # 1 hour
            "domain_info": 7200,  # 2 hours
            "email_info": 86400,  # 24 hours
            "breach_data": 604800,  # 7 days
            "web_content": 1800,  # 30 minutes
            "api_response": 3600,  # 1 hour
        }

        self._ensure_cache_dir()
        self._load_cache()

    def _ensure_cache_dir(self):
        """Ensure cache directory exists"""
        os.makedirs(self.cache_dir, exist_ok=True)

    def _load_cache(self):
        """Load cache from disk"""
        cache_file = os.path.join(self.cache_dir, "osint_cache.json")
        if not os.path.exists(cache_file):
            return

        try:
            with open(cache_file, "r") as f:
                data = json.load(f)

            for entry_data in data.get("entries", []):
                entry = CacheEntry.from_dict(entry_data)
                if not entry.is_expired():
                    self._cache[entry.key] = entry

            self.utils.logger.info(f"Loaded {len(self._cache)} cache entries")

        except Exception as e:
            self.utils.logger.warning(f"Failed to load cache: {e}")

    def _save_cache(self):
        """Save cache to disk"""
        cache_file = os.path.join(self.cache_dir, "osint_cache.json")

        try:
            # Clean expired entries
            self._cleanup_expired()

            data = {
                "timestamp": datetime.now().isoformat(),
                "entries": [entry.to_dict() for entry in self._cache.values()],
            }

            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.utils.logger.warning(f"Failed to save cache: {e}")

    def _generate_key(self, service: str, operation: str, params: Dict) -> str:
        """Generate cache key from service, operation and parameters"""
        # Sort params for consistent key generation
        param_str = json.dumps(params, sort_keys=True)
        key_content = f"{service}:{operation}:{param_str}"
        return hashlib.md5(key_content.encode()).hexdigest()

    def _cleanup_expired(self):
        """Remove expired entries"""
        expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
        for key in expired_keys:
            del self._cache[key]

    def _enforce_size_limit(self):
        """Enforce maximum cache size by removing least recently used items"""
        if len(self._cache) <= self.max_size:
            return

        # Sort by last accessed time (oldest first)
        sorted_entries = sorted(self._cache.items(), key=lambda x: x[1].last_accessed)

        # Remove oldest entries
        to_remove = len(self._cache) - self.max_size
        for key, _ in sorted_entries[:to_remove]:
            del self._cache[key]

    def get(self, service: str, operation: str, params: Dict) -> Optional[Any]:
        """Get cached result"""
        with self._lock:
            key = self._generate_key(service, operation, params)

            if key in self._cache:
                entry = self._cache[key]
                if not entry.is_expired():
                    entry.access()
                    self.utils.logger.debug(f"Cache hit: {service}:{operation}")
                    return entry.data
                else:
                    # Remove expired entry
                    del self._cache[key]

            self.utils.logger.debug(f"Cache miss: {service}:{operation}")
            return None

    def put(
        self,
        service: str,
        operation: str,
        params: Dict,
        data: Any,
        ttl_seconds: Optional[int] = None,
    ):
        """Store result in cache"""
        with self._lock:
            key = self._generate_key(service, operation, params)

            # Determine TTL
            if ttl_seconds is None:
                ttl_seconds = self.default_ttl.get(
                    operation, self.default_ttl.get("api_response", 3600)
                )

            entry = CacheEntry(key, data, ttl_seconds)
            self._cache[key] = entry

            # Enforce size limits
            self._enforce_size_limit()

            # Save to disk periodically (every 10 operations)
            if len(self._cache) % 10 == 0:
                self._save_cache()

            self.utils.logger.debug(
                f"Cached: {service}:{operation} (TTL: {ttl_seconds}s)"
            )

    def invalidate(
        self,
        service: Optional[str] = None,
        operation: Optional[str] = None,
        params: Optional[Dict] = None,
    ):
        """Invalidate cache entries"""
        with self._lock:
            if service and operation and params:
                # Invalidate specific entry
                key = self._generate_key(service, operation, params)
                if key in self._cache:
                    del self._cache[key]
            elif service and operation:
                # Invalidate all entries for service:operation
                keys_to_remove = []
                for key, entry in self._cache.items():
                    # This is a simplified check - in practice you'd need to decode the key
                    if f"{service}:{operation}:" in key:
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    del self._cache[key]
            else:
                # Clear all cache
                self._cache.clear()

            self._save_cache()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            total_entries = len(self._cache)
            expired_entries = sum(
                1 for entry in self._cache.values() if entry.is_expired()
            )

            if total_entries > 0:
                total_accesses = sum(
                    entry.access_count for entry in self._cache.values()
                )
                avg_accesses = total_accesses / total_entries
            else:
                avg_accesses = 0

            return {
                "total_entries": total_entries,
                "expired_entries": expired_entries,
                "active_entries": total_entries - expired_entries,
                "average_accesses": avg_accesses,
                "max_size": self.max_size,
                "hit_rate": avg_accesses,  # Simplified hit rate calculation
            }

    def cleanup(self):
        """Perform maintenance cleanup"""
        with self._lock:
            self._cleanup_expired()
            self._enforce_size_limit()
            self._save_cache()


# Global cache instance
cache = OSINTCache()


def cached_request(
    service: str, operation: str, params: Dict, ttl_seconds: Optional[int] = None
):
    """
    Decorator for caching function results

    Usage:
        @cached_request('shodan', 'host', ttl_seconds=3600)
        def get_shodan_host(ip):
            # API call here
            return result
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Use params for cache key
            cache_params = params.copy()
            cache_params.update(kwargs)

            # Check cache first
            cached_result = cache.get(service, operation, cache_params)
            if cached_result is not None:
                return cached_result

            # Execute function
            result = func(*args, **kwargs)

            # Cache result
            if result is not None:
                cache.put(service, operation, cache_params, result, ttl_seconds)

            return result

        return wrapper

    return decorator
