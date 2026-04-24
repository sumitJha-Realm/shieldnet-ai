"""URL structure analysis — local, no external API calls."""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import parse_qs, unquote, urlparse

from Levenshtein import distance as levenshtein_distance

from enricher.config import BRAND_DOMAINS, SUSPICIOUS_KEYWORDS
from enricher.models import BrandImpersonation, URLStructure


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _extract_subdomain(hostname: str) -> tuple[str, str, int]:
    """Return (subdomain_part, registered_domain, subdomain_depth)."""
    parts = hostname.lower().split(".")
    # Handle 2-level ccTLDs: .co.in, .org.in, .gov.in, .ac.in, .net.in, .co.uk
    two_level_tlds = {
        "co.in", "org.in", "gov.in", "ac.in", "net.in", "gen.in", "res.in",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "org.au", "gov.au",
    }
    suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
    if suffix in two_level_tlds and len(parts) >= 3:
        reg_domain = ".".join(parts[-3:])
        sub_parts = parts[:-3]
    elif len(parts) >= 2:
        reg_domain = ".".join(parts[-2:])
        sub_parts = parts[:-2]
    else:
        reg_domain = hostname
        sub_parts = []

    subdomain = ".".join(sub_parts) if sub_parts else ""
    return subdomain, reg_domain, len(sub_parts)


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _count_special_chars(path: str) -> int:
    return sum(1 for c in path if c in "%@!~")


def _detect_keywords(url_lower: str) -> list[str]:
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]


def analyze_structure(url: str) -> URLStructure:
    """Parse and analyze URL structure.  Pure local computation."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    subdomain, reg_domain, depth = _extract_subdomain(hostname)

    path_decoded = unquote(parsed.path or "/")
    query_decoded = unquote(parsed.query or "")
    url_lower = url.lower()

    hyphen_count = hostname.count("-")

    return URLStructure(
        scheme=parsed.scheme or "http",
        domain=reg_domain,
        subdomain=subdomain,
        path=parsed.path or "/",
        query_params=parse_qs(parsed.query) if parsed.query else {},
        fragment=parsed.fragment or "",
        url_length=len(url),
        entropy=round(_shannon_entropy(url), 3),
        subdomain_depth=depth,
        is_ip_address=_is_ip(hostname),
        special_char_count=_count_special_chars(path_decoded + query_decoded),
        has_url_encoding="%" in (parsed.path or "") + (parsed.query or ""),
        suspicious_keywords=_detect_keywords(url_lower),
        excessive_hyphens=hyphen_count >= 3,
        hyphen_count=hyphen_count,
    )


def _extract_sld(hostname: str) -> str:
    """Extract the second-level domain label from a hostname.

    e.g. 'login.nicc^2-portal-update.tk' → 'nicc^2-portal-update'
         'rbl.org.in' → 'rbl'
         'rbi.org.in' → 'rbi'
    """
    _, reg_domain, _ = _extract_subdomain(hostname)
    parts = reg_domain.split(".")
    return parts[0] if parts else hostname


def _tokenize_sld(sld: str) -> list[str]:
    """Split an SLD by hyphens, digits, and special chars to extract brand tokens.

    e.g. 'nicc^2-portal-update' → ['nicc', 'portal', 'update']
         'sbi-login' → ['sbi', 'login']
    """
    tokens = re.split(r"[-_^~.+\d]+", sld)
    return [t for t in tokens if len(t) >= 2]


def detect_brand_impersonation(domain: str) -> BrandImpersonation:
    """Check Levenshtein edit distance against known brand domains.

    Uses three strategies:
      1. Exact full-domain match (e.g. rbi.org.in → exact)
      2. Full registered-domain vs known domain
      3. Token-level: split SLD by hyphens/special chars and compare
         each token against known brand SLDs (catches nicc→nic, sbl→sbi)
    """
    domain_lower = domain.lower()

    # Strategy 1: exact match on the full hostname
    if domain_lower in BRAND_DOMAINS:
        return BrandImpersonation(
            closest_brand=BRAND_DOMAINS[domain_lower],
            known_domain=domain_lower,
            edit_distance=0,
            is_exact_match=True,
        )

    # Also check the registered domain (strip subdomains)
    _, reg_domain, _ = _extract_subdomain(domain_lower)
    if reg_domain in BRAND_DOMAINS:
        return BrandImpersonation(
            closest_brand=BRAND_DOMAINS[reg_domain],
            known_domain=reg_domain,
            edit_distance=0,
            is_exact_match=True,
        )

    # Pre-compute known brand SLDs for token comparison
    brand_slds: dict[str, tuple[str, str]] = {}  # sld → (full_domain, brand_name)
    for known, brand in BRAND_DOMAINS.items():
        known_parts = known.split(".")
        sld = known_parts[0]
        brand_slds[sld] = (known, brand)

    # Strategy 2: registered-domain-level comparison
    best_dist = 999
    best_domain = ""
    best_brand = ""
    for known, brand in BRAND_DOMAINS.items():
        d = levenshtein_distance(reg_domain, known)
        if d < best_dist:
            best_dist = d
            best_domain = known
            best_brand = brand

    # Strategy 3: token-level comparison against brand SLDs
    sld = _extract_sld(domain_lower)
    tokens = _tokenize_sld(sld)
    # Also include the full SLD as a candidate
    candidates = [sld] + tokens

    for candidate in candidates:
        for known_sld, (full_domain, brand_name) in brand_slds.items():
            d = levenshtein_distance(candidate, known_sld)
            if d < best_dist:
                best_dist = d
                best_domain = full_domain
                best_brand = brand_name

    return BrandImpersonation(
        closest_brand=best_brand,
        known_domain=best_domain,
        edit_distance=best_dist,
        is_exact_match=False,
    )
