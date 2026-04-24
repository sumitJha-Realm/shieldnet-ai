"""IP & hosting analysis — GeoIP via ip-api.com free tier, ASN classification."""

from __future__ import annotations

import asyncio
import logging

import httpx

from enricher.config import CLOUD_ASNS, GEOIP_TIMEOUT, SUSPICIOUS_ASNS
from enricher.models import HostingResult

logger = logging.getLogger(__name__)

# ip-api.com fields: query, country, countryCode, city, isp, as, org
_IP_API_URL = "http://ip-api.com/json/{ip}?fields=query,country,countryCode,city,isp,as,org"


async def analyze_hosting(ip: str) -> HostingResult:
    """GeoIP + ASN lookup for a resolved IP address."""
    result = HostingResult(ip=ip)
    if not ip:
        return result

    try:
        async with httpx.AsyncClient(timeout=GEOIP_TIMEOUT) as client:
            resp = await client.get(_IP_API_URL.format(ip=ip))
            resp.raise_for_status()
            data = resp.json()

        result.country = data.get("country", "unknown")
        result.country_code = data.get("countryCode", "")
        result.city = data.get("city", "unknown")
        result.isp = data.get("isp", "unknown")

        as_field = data.get("as", "")  # e.g. "AS13335 Cloudflare, Inc."
        result.asn_org = data.get("org", "unknown")
        if as_field:
            parts = as_field.split(None, 1)
            asn_str = parts[0] if parts else ""
            if asn_str.startswith("AS"):
                try:
                    result.asn = int(asn_str[2:])
                except ValueError:
                    pass

        # ── Classify hosting type ────────────────────────────────────────
        as_key = f"AS{result.asn}" if result.asn else ""

        if as_key in CLOUD_ASNS:
            result.hosting_type = "cloud"
            result.cloud_provider = CLOUD_ASNS[as_key]
        elif any(cdn in result.asn_org.lower() for cdn in ("cloudflare", "akamai", "fastly", "cdn")):
            result.hosting_type = "cdn"
            result.cloud_provider = result.asn_org
        elif result.asn in SUSPICIOUS_ASNS:
            result.hosting_type = "bulletproof"
        elif "shared" in result.isp.lower() or "hosting" in result.isp.lower():
            result.hosting_type = "shared"
        else:
            result.hosting_type = "dedicated"

        result.is_suspicious_asn = result.asn in SUSPICIOUS_ASNS

    except httpx.TimeoutException:
        logger.warning("GeoIP timeout for %s", ip)
    except Exception as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)

    return result
