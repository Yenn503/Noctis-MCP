"""
In-memory caching system for Noctis-MCP
Thread-safe LRU cache with TTL support
"""

import threading
from datetime import datetime, timedelta
from typing import Any, Optional, Dict
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


class IntelligenceCache:
    """
    Thread-safe in-memory cache with TTL (Time To Live)
    Much faster than file-based caching for local project
    """

    def __init__(self, ttl_hours: int = 24, max_size: int = 1000):
        """
        Initialize cache

        Args:
            ttl_hours: How long cache entries are valid (default 24 hours)
            max_size: Maximum number of entries before LRU eviction
        """
        self.cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.lock = threading.Lock()
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

        logger.info(f"[Cache] Initialized with TTL={ttl_hours}h, max_size={max_size}")

    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value if exists and not expired

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self.lock:
            entry = self.cache.get(key)

            if entry is None:
                self.misses += 1
                return None

            # Check if expired
            age = datetime.now() - entry['timestamp']
            if age > self.ttl:
                # Remove expired entry
                del self.cache[key]
                self.misses += 1
                logger.debug(f"[Cache] Expired: {key} (age: {age})")
                return None

            # Move to end (LRU)
            self.cache.move_to_end(key)
            self.hits += 1

            logger.debug(f"[Cache] HIT: {key} (age: {age.seconds}s)")
            return entry['data']

    def set(self, key: str, data: Any) -> None:
        """
        Store value in cache

        Args:
            key: Cache key
            data: Value to cache
        """
        with self.lock:
            # Evict oldest if at capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                logger.debug(f"[Cache] Evicted oldest: {oldest_key}")

            self.cache[key] = {
                'data': data,
                'timestamp': datetime.now()
            }

            # Move to end (most recent)
            self.cache.move_to_end(key)

            logger.debug(f"[Cache] SET: {key}")

    def invalidate(self, key: str) -> bool:
        """
        Remove specific key from cache

        Args:
            key: Cache key to remove

        Returns:
            True if key was found and removed
        """
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                logger.debug(f"[Cache] Invalidated: {key}")
                return True
            return False

    def clear(self) -> None:
        """Clear entire cache"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            logger.info("[Cache] Cleared all entries")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache stats
        """
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0

            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': round(hit_rate, 2),
                'ttl_hours': self.ttl.total_seconds() / 3600
            }


class EmbeddingCache:
    """
    Specialized cache for text embeddings
    Reduces redundant embedding generation for same queries
    """

    def __init__(self, max_size: int = 500):
        """
        Initialize embedding cache

        Args:
            max_size: Maximum number of embeddings to cache
        """
        self.cache: OrderedDict[str, list] = OrderedDict()
        self.lock = threading.Lock()
        self.max_size = max_size

        logger.info(f"[EmbeddingCache] Initialized with max_size={max_size}")

    def get(self, text: str) -> Optional[list]:
        """
        Get cached embedding for text

        Args:
            text: Text to lookup

        Returns:
            Embedding vector or None
        """
        with self.lock:
            if text in self.cache:
                # Move to end (LRU)
                self.cache.move_to_end(text)
                return self.cache[text]
            return None

    def set(self, text: str, embedding: list) -> None:
        """
        Cache embedding for text

        Args:
            text: Input text
            embedding: Embedding vector
        """
        with self.lock:
            # Evict oldest if at capacity
            if len(self.cache) >= self.max_size and text not in self.cache:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]

            self.cache[text] = embedding
            self.cache.move_to_end(text)

    def clear(self) -> None:
        """Clear all cached embeddings"""
        with self.lock:
            self.cache.clear()
            logger.info("[EmbeddingCache] Cleared all embeddings")
