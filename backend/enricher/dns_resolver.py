"""DNS resolution — async live lookups for A, AAAA, CNAME, MX, NS, TXT, DNSSEC, rDNS."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import dns.resolver
import dns.reversename
import dns.rdatatype
import dns.flags

from enricher.config import DNS_TIMEOUT
from enricher.models import DNSResult

logger = logging.getLogger(__name__)


def _sync_resolve(domain: str, rdtype: str, timeout: float) -> list[str]:
    """Blocking DNS resolve — will be wrapped in executor."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, rdtype)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout, Exception):
        return []


def _sync_reverse_dns(ip: str, timeout: float) -> str:
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(rev_name, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return ""


def _check_dnssec(domain: str, timeout: float) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        # Request DNSKEY — if it exists, DNSSEC is configured
        resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False


async def resolve_dns(domain: str) -> DNSResult:
    """Run all DNS lookups concurrently via executor, return DNSResult."""
    loop = asyncio.get_running_loop()
    result = DNSResult()

    try:
        # Run all record-type lookups in parallel
        tasks: dict[str, Any] = {}
        for rdtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            tasks[rdtype] = loop.run_in_executor(
                None, _sync_resolve, domain, rdtype, DNS_TIMEOUT
            )
        tasks["dnssec"] = loop.run_in_executor(
            None, _check_dnssec, domain, DNS_TIMEOUT
        )

        outcomes = {}
        for key, coro in tasks.items():
            try:
                outcomes[key] = await asyncio.wait_for(coro, timeout=DNS_TIMEOUT + 1)
            except (asyncio.TimeoutError, Exception) as exc:
                logger.debug("DNS %s lookup for %s failed: %s", key, domain, exc)
                outcomes[key] = [] if key != "dnssec" else False

        a_records = outcomes.get("A", [])
        result.a_records = a_records
        result.aaaa_records = outcomes.get("AAAA", [])
        result.cname_records = outcomes.get("CNAME", [])
        result.mx_records = outcomes.get("MX", [])
        result.ns_records = outcomes.get("NS", [])
        result.txt_records = outcomes.get("TXT", [])
        result.a_record_count = len(a_records)
        result.cname_chain_depth = len(result.cname_records)
        result.has_dnssec = bool(outcomes.get("dnssec", False))

        if a_records:
            result.resolves = True
            result.resolution_status = "success"
            # Reverse DNS on first A record
            rdns = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_reverse_dns, a_records[0], DNS_TIMEOUT),
                timeout=DNS_TIMEOUT + 1,
            )
            result.reverse_dns = rdns
            result.reverse_dns_matches = domain.lower() in rdns.lower() if rdns else False
        else:
            result.resolution_status = "nxdomain"

    except Exception as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)
        result.resolution_status = "error"

    return result
