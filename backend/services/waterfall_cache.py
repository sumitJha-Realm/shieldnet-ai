"""Waterfall enforcement cache — sub-10ms lookups for known URLs.

Implements a three-tier cascade:
  1. L1: In-memory LRU cache (< 1ms)   — recent scan results
  2. L2: MongoDB lookup by exact URL    — previously scanned URLs
  3. L3: Vector DB semantic search      — full AI pipeline

This eliminates redundant embedding + vector-search calls for
repeat submissions and achieves the "Active Prevention" latency
target of < 10ms for cache hits.
"""

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_MAX_SIZE = 10_000
DEFAULT_TTL_SECS = 300  # 5 minutes


@dataclass
class CacheEntry:
    """A single cached scan result."""
    result: dict
    timestamp: float = field(default_factory=time.monotonic)


class WaterfallCache:
    """LRU in-memory cache with TTL for the scan pipeline."""

    def __init__(self, max_size: int = DEFAULT_MAX_SIZE, ttl_secs: int = DEFAULT_TTL_SECS):
        self._max_size = max_size
        self._ttl = ttl_secs
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._hits = 0
        self._misses = 0

    # ── Public API ───────────────────────────────────────────────────────

    def get(self, url: str) -> Optional[dict]:
        """L1 lookup — returns cached result or None.

        Evicts expired entries on access.
        """
        entry = self._store.get(url)
        if entry is None:
            self._misses += 1
            return None

        # Check TTL
        age = time.monotonic() - entry.timestamp
        if age > self._ttl:
            del self._store[url]
            self._misses += 1
            logger.debug("Cache expired for %s (age=%.1fs)", url, age)
            return None

        # Move to end (most recently used)
        self._store.move_to_end(url)
        self._hits += 1
        logger.info("Cache HIT for %s (age=%.1fs, latency<1ms)", url, age)
        return entry.result

    def put(self, url: str, result: dict) -> None:
        """Store a scan result in the cache."""
        if url in self._store:
            self._store.move_to_end(url)
            self._store[url] = CacheEntry(result=result)
        else:
            if len(self._store) >= self._max_size:
                self._store.popitem(last=False)  # Evict oldest
            self._store[url] = CacheEntry(result=result)

    def invalidate(self, url: str) -> bool:
        """Remove a specific URL from cache (e.g., on status change)."""
        if url in self._store:
            del self._store[url]
            return True
        return False

    def clear(self) -> None:
        """Flush the entire cache."""
        self._store.clear()

    @property
    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "maxSize": self._max_size,
            "ttlSecs": self._ttl,
            "hits": self._hits,
            "misses": self._misses,
            "hitRate": round(self._hits / total, 3) if total > 0 else 0.0,
        }
