"""Main orchestrator — runs all enrichment steps in parallel."""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

from enricher.cache import get_enrichment_cache
from enricher.config import (
    CACHE_TTL_DNS_DEFAULT,
    CACHE_TTL_GEOIP,
    CACHE_TTL_WHOIS,
)
from enricher.dns_resolver import resolve_dns
from enricher.hosting import analyze_hosting
from enricher.models import EnrichmentResult
from enricher.narrative import build_narrative
from enricher.redirects import follow_redirects
from enricher.structure import analyze_structure, detect_brand_impersonation
from enricher.tls_inspector import inspect_tls
from enricher.whois_lookup import lookup_whois

logger = logging.getLogger(__name__)


async def enrich_url(url: str) -> EnrichmentResult:
    """Run full behavioral enrichment pipeline for a URL.

    Steps execute in parallel where possible:
      1. URL structure analysis  (local, instant)
      2. DNS + WHOIS + TLS + Redirects  (parallel async I/O)
      3. Hosting/GeoIP (depends on DNS IP)  — sequential after DNS
      4. Narrative generation  (local, instant)

    Total target: < 3 seconds.
    """
    start = time.monotonic()
    cache = get_enrichment_cache()
    result = EnrichmentResult(url=url)
    errors: list[str] = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme or "http"

    # ── Step 1: Local structure analysis (instant) ───────────────────────
    result.structure = analyze_structure(url)
    result.brand_impersonation = detect_brand_impersonation(result.structure.domain)

    # ── Step 2: Parallel external lookups ────────────────────────────────
    # Check caches first
    cached_dns = cache.get("dns", hostname)
    cached_whois = cache.get("whois", result.structure.domain)

    dns_task = _wrap(resolve_dns(hostname), "DNS", errors) if not cached_dns else _noop(cached_dns)
    whois_task = _wrap(lookup_whois(result.structure.domain), "WHOIS", errors) if not cached_whois else _noop(cached_whois)
    tls_task = _wrap(inspect_tls(hostname), "TLS", errors) if scheme == "https" else _noop(result.tls)
    redirect_task = _wrap(follow_redirects(url), "Redirects", errors)

    dns_result, whois_result, tls_result, redirect_result = await asyncio.gather(
        dns_task, whois_task, tls_task, redirect_task,
    )

    from enricher.models import DNSResult, WHOISResult, TLSResult, RedirectResult
    result.dns = dns_result if dns_result is not None else DNSResult()
    result.whois = whois_result if whois_result is not None else WHOISResult()
    result.tls = tls_result if tls_result is not None else TLSResult()
    result.redirects = redirect_result if redirect_result is not None else RedirectResult()

    # Cache DNS + WHOIS results
    if not cached_dns and result.dns.resolves:
        ttl = result.dns.ttl if result.dns.ttl > 0 else CACHE_TTL_DNS_DEFAULT
        cache.put("dns", hostname, result.dns, ttl)
    if not cached_whois and result.whois.domain_age_days >= 0:
        cache.put("whois", result.structure.domain, result.whois, CACHE_TTL_WHOIS)

    # ── Step 3: Hosting/GeoIP (needs resolved IP from DNS) ───────────────
    primary_ip = result.dns.a_records[0] if result.dns.a_records else ""
    if primary_ip:
        cached_hosting = cache.get("geoip", primary_ip)
        if cached_hosting:
            result.hosting = cached_hosting
        else:
            try:
                result.hosting = await _wrap(analyze_hosting(primary_ip), "Hosting", errors)
                cache.put("geoip", primary_ip, result.hosting, CACHE_TTL_GEOIP)
            except Exception:
                pass

    # ── Step 4: Narrative ────────────────────────────────────────────────
    result.narrative = build_narrative(result)
    result.errors = errors
    result.enrichment_time_ms = round((time.monotonic() - start) * 1000, 1)

    logger.info(
        "Enrichment complete for %s in %.1fms (errors: %d)",
        url, result.enrichment_time_ms, len(errors),
    )
    return result


async def _wrap(coro, label: str, errors: list[str]):
    """Run a coroutine, catching any exception and recording it."""
    try:
        return await coro
    except Exception as exc:
        errors.append(f"{label}: {exc}")
        logger.warning("Enrichment step %s failed: %s", label, exc)
        return None


async def _noop(value):
    """Return a pre-computed value as a coroutine (for cache hits)."""
    return value
