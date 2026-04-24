"""In-memory LRU cache with per-key TTL for enrichment results."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _Entry:
    value: Any
    expires_at: float


class EnrichmentCache:
    """Thread-safe-ish LRU cache with per-key TTL.

    Cache categories:
      - whois:  24h TTL
      - geoip:  7d  TTL
      - dns:    respect TTL from response (fallback 5min)
    """

    def __init__(self, max_size: int = 5000):
        self._store: OrderedDict[str, _Entry] = OrderedDict()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _make_key(self, category: str, key: str) -> str:
        return f"{category}:{key}"

    def get(self, category: str, key: str) -> Any | None:
        ck = self._make_key(category, key)
        entry = self._store.get(ck)
        if entry is None:
            self._misses += 1
            return None
        if time.monotonic() > entry.expires_at:
            del self._store[ck]
            self._misses += 1
            return None
        self._store.move_to_end(ck)
        self._hits += 1
        return entry.value

    def put(self, category: str, key: str, value: Any, ttl_secs: int) -> None:
        ck = self._make_key(category, key)
        self._store[ck] = _Entry(value=value, expires_at=time.monotonic() + ttl_secs)
        self._store.move_to_end(ck)
        while len(self._store) > self._max_size:
            self._store.popitem(last=False)

    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "maxSize": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hitRate": round(self._hits / total, 3) if total else 0.0,
        }


# Module-level singleton
_cache = EnrichmentCache()


def get_enrichment_cache() -> EnrichmentCache:
    return _cache
