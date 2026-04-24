"""WHOIS / domain registration — async live lookup."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import whois  # python-whois

from enricher.config import WHOIS_TIMEOUT
from enricher.models import WHOISResult

logger = logging.getLogger(__name__)


def _sync_whois(domain: str) -> WHOISResult:
    """Blocking WHOIS query — will be wrapped in executor."""
    result = WHOISResult()
    try:
        w = whois.whois(domain)

        # Registrar
        result.registrar = w.registrar or "unknown"

        # Creation date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if isinstance(creation, str):
                try:
                    creation = datetime.fromisoformat(creation)
                except ValueError:
                    creation = None
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                result.creation_date = creation.isoformat()
                age = datetime.now(timezone.utc) - creation
                result.domain_age_days = max(age.days, 0)

        # Expiry date
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            if isinstance(expiry, str):
                try:
                    expiry = datetime.fromisoformat(expiry)
                except ValueError:
                    expiry = None
            if expiry:
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                result.expiry_date = expiry.isoformat()
                days_left = (expiry - datetime.now(timezone.utc)).days
                result.days_until_expiry = max(days_left, 0)
                result.expires_soon = days_left < 30

        # Registration country
        country = w.country
        if country:
            result.registration_country = country

        # WHOIS privacy — heuristic: look for common privacy phrases
        raw = str(w.text or "") + str(w.name or "") + str(w.org or "")
        privacy_markers = ("privacy", "redacted", "data protected", "whoisguard",
                           "domains by proxy", "contact privacy", "withheld")
        result.whois_privacy = any(m in raw.lower() for m in privacy_markers)

    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

    return result


async def lookup_whois(domain: str) -> WHOISResult:
    """Async wrapper around blocking WHOIS query."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_whois, domain),
            timeout=WHOIS_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        logger.warning("WHOIS timeout for %s", domain)
        return WHOISResult()
    except Exception as exc:
        logger.warning("WHOIS lookup error for %s: %s", domain, exc)
        return WHOISResult()
