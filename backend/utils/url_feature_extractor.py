"""URL feature extraction and analysis utilities."""

import hashlib
import math
import re
import logging
from urllib.parse import urlparse, unquote, parse_qs
import random

from utils.dga_detector import (
    detect_dga,
    detect_homoglyphs,
    compute_tld_risk,
    compute_structural_threat_score,
    build_semantic_features,
)
from enricher.structure import detect_brand_impersonation

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".work", ".icu", ".cam", ".monster", ".rest", ".fit",
}

KNOWN_HOSTING_PROVIDERS = [
    "aws", "azure", "gcp", "digitalocean", "linode", "vultr",
    "cloudflare", "fastly", "akamai", "ovh", "hetzner",
]

GEO_LOCATIONS = ["US", "IN", "CN", "RU", "DE", "NL", "SG", "BR", "UA", "RO"]

DEPARTMENTS = [
    "Ministry of Finance", "Ministry of Defence", "Ministry of Home Affairs",
    "Ministry of External Affairs", "Ministry of Health", "Ministry of Education",
    "Ministry of IT & Telecom", "UIDAI", "NIC", "CERT-IN",
    "Ministry of Railways", "Ministry of Commerce",
]

# ── Payload detection patterns ───────────────────────────────────────────
_PAYLOAD_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("xss", re.compile(r"<script|onerror\s*=|onload\s*=|javascript:|<svg|<img\s[^>]*on\w+=|<iframe|<body\s[^>]*on\w+=|<input\s[^>]*on\w+=|<details[^>]*on\w+=", re.IGNORECASE)),
    ("sqli", re.compile(r"(?:'\s*OR\s|UNION\s+SELECT|DROP\s+TABLE|EXEC\s+xp_|SLEEP\s*\(|WAITFOR\s+DELAY|information_schema|CONVERT\s*\()", re.IGNORECASE)),
    ("path_traversal", re.compile(r"\.\./|\.\.\\|%2e%2e|%252e|%c0%af|/proc/self|/etc/passwd|/etc/shadow", re.IGNORECASE)),
    ("command_injection", re.compile(r";\s*cat\s|;\s*ping\s|\|\s*wget\s|\|\s*curl\s|`[^`]+`|\$\([^)]+\)|&&\s*curl|;\s*base64", re.IGNORECASE)),
    ("open_redirect", re.compile(r"(?:redirect|url|next|return|goto|continue|redir|returnUrl|target|dest)\s*=\s*https?://", re.IGNORECASE)),
    ("ssrf", re.compile(r"169\.254\.169\.254|localhost|127\.0\.0\.1|\[::1\]|metadata\.google\.internal|internal-api\.local|gopher://|dict://", re.IGNORECASE)),
    ("credential_harvest", re.compile(r"(?:formAction|webhook|postback|notify|callback)\s*=\s*https?://", re.IGNORECASE)),
    ("malware_download", re.compile(r"\.(?:exe|scr|bat|cmd|pif|com|hta|vbs|ps1|jar|msi|wsf|docm|xlsm)(?:\?|$)", re.IGNORECASE)),
    ("base64_payload", re.compile(r"(?:data|payload|token|state|code|enc)\s*=\s*[A-Za-z0-9+/]{20,}={0,2}", re.IGNORECASE)),
    ("obfuscated_path", re.compile(r"/\.git/|/\.env|/\.aws/|/wp-admin/|/actuator/|/debug/|/console|/server-status|\.\.;/", re.IGNORECASE)),
]


def detect_payload_types(url: str) -> list[str]:
    """Detect attack payload types present in the URL."""
    decoded = unquote(unquote(url))  # double-decode for %25xx
    found: list[str] = []
    for name, pattern in _PAYLOAD_PATTERNS:
        if pattern.search(decoded) or pattern.search(url):
            found.append(name)
    return found


def classify_payload_severity(payload_types: list[str]) -> str:
    """Map detected payload types to a severity level."""
    critical = {"command_injection", "ssrf", "sqli"}
    high = {"xss", "path_traversal", "credential_harvest", "malware_download"}
    if critical & set(payload_types):
        return "critical"
    if high & set(payload_types):
        return "high"
    if payload_types:
        return "medium"
    return "low"


def derive_payload_signature(payload_types: list[str]) -> str:
    """Build a normalised payload signature string."""
    if not payload_types:
        return ""
    return "+".join(sorted(payload_types))


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_features(url: str) -> dict:
    """Extract security-relevant features from a URL."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        parsed = urlparse(f"http://{url}")

    domain = parsed.hostname or parsed.netloc or url
    path = parsed.path or "/"
    path_depth = len([p for p in path.split("/") if p])

    # Check for IP address in domain
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))

    # Check suspicious TLD
    has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # Entropy of the full URL
    entropy = calculate_entropy(url)

    # Encoded characters
    contains_encoded = "%" in url or unquote(url) != url

    # Subdomain count
    parts = domain.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # Parse query parameters (structured storage)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # Detect payload types in the URL
    payload_types = detect_payload_types(url)

    # Simulate dynamic features (in production these would come from real lookups)
    # Domain age: deterministic based on domain hash so the same domain always
    # gets the same age.  Suspicious TLDs skew younger (1–365 days), well-known
    # TLDs skew older (180–3650 days), others use full range.
    _WELL_KNOWN_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co", ".us", ".uk", ".in"}
    domain_hash = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    if has_suspicious_tld:
        domain_age_days = (domain_hash % 365) + 1        # 1–365 days
    elif any(domain.endswith(t) for t in _WELL_KNOWN_TLDS):
        domain_age_days = (domain_hash % 3470) + 180     # 180–3650 days
    else:
        domain_age_days = (domain_hash % 3650) + 1       # 1–3650 days
    ssl_valid = random.random() > 0.3 if not has_suspicious_tld else random.random() > 0.7
    is_shared_hosting = random.random() > 0.5
    is_cloud_hosted = random.random() > 0.6
    hosting_provider = random.choice(KNOWN_HOSTING_PROVIDERS + ["unknown-host-provider"] * 3)
    geo_location = random.choice(GEO_LOCATIONS)

    # DNS status
    if domain_age_days < 7:
        dns_status = random.choice(["active", "parked"])
    elif has_suspicious_tld:
        dns_status = random.choice(["active", "suspended", "parked"])
    else:
        dns_status = "active"

    hosting_flags = {
        "isSharedHosting": is_shared_hosting,
        "isCloudHosted": is_cloud_hosted,
        "hostingProvider": hosting_provider,
        "geoLocation": geo_location,
        "sslValid": ssl_valid,
        "domainAgeDays": domain_age_days,
    }

    url_structure = {
        "pathDepth": path_depth,
        "hasIpAddress": has_ip,
        "hasSuspiciousTld": has_suspicious_tld,
        "entropyScore": entropy,
        "containsEncodedChars": contains_encoded,
        "subdomainCount": subdomain_count,
    }

    return {
        "domain": domain,
        "dnsStatus": dns_status,
        "hostingFlags": hosting_flags,
        "urlStructure": url_structure,
        "queryParams": query_params,
        "payloadTypes": payload_types,
    }


def enrich_features(url: str, base_features: dict, modules: dict | None = None) -> dict:
    """Run advanced detectors (DGA, homoglyph, TLD, structural) on top of base features.

    *modules* is the detectionModules dict from scan rules — any module whose
    key is False will be skipped.

    Returns the base features dict augmented with:
      - dgaAnalysis, homoglyphAnalysis, tldRisk, structuralAnalysis, semanticFeatures
    """
    domain = base_features["domain"]
    if modules is None:
        modules = {}

    dga = detect_dga(domain) if modules.get("dgaDetection", True) else {
        "isDGA": False, "dgaScore": 0.0, "dgaSignals": [], "consonantRatio": 0.0,
        "bigramLegitimacy": 1.0, "domainLength": len(domain),
    }
    homoglyph = detect_homoglyphs(domain) if modules.get("homoglyphDetection", True) else {
        "hasHomoglyphs": False, "homoglyphSignals": [], "targetDomain": None, "visualSimilarity": 0.0,
    }
    tld_risk = compute_tld_risk(domain)
    structural = compute_structural_threat_score(url, domain) if modules.get("structuralBypass", True) else {
        "structuralScore": 0.0, "structuralSignals": [], "bypassTechniques": [],
    }
    semantic = build_semantic_features(url, base_features, dga, homoglyph, tld_risk, structural)

    # Brand impersonation (Levenshtein distance against known gov domains)
    brand_dict = {}
    if modules.get("brandImpersonation", True):
        brand = detect_brand_impersonation(domain)
        brand_dict = brand.model_dump()
    else:
        brand_dict = {"closest_brand": None, "known_domain": None, "edit_distance": 999, "is_exact_match": False}

    base_features["dgaAnalysis"] = dga
    base_features["homoglyphAnalysis"] = homoglyph
    base_features["tldRisk"] = tld_risk
    base_features["structuralAnalysis"] = structural
    base_features["semanticFeatures"] = semantic
    base_features["brandImpersonation"] = brand_dict

    return base_features


def build_summary_text(url: str, features: dict, classification: str = "",
                       risk_score: float = 0.0, status: str = "",
                       scan_count: int = 0) -> str:
    """Build a natural language summary from ALL document fields for embedding.

    Fuses textual URL info, non-textual metadata, and classification results
    into a single composite text stored as summaryText and used for embedding.
    """
    hf = features["hostingFlags"]
    us = features["urlStructure"]
    dns = features["dnsStatus"]

    parts = [
        f"URL analysis for {features['domain']}",
        f"domain age {hf['domainAgeDays']} days",
        f"{'valid' if hf['sslValid'] else 'no valid'} SSL",
        f"{'shared' if hf['isSharedHosting'] else 'dedicated'} hosting",
        f"hosted by {hf['hostingProvider']}",
        f"geo {hf['geoLocation']}",
        f"path depth {us['pathDepth']}",
        f"entropy {us['entropyScore']:.2f}",
    ]

    if classification:
        parts.append(f"threat classification {classification}")
    if risk_score:
        parts.append(f"risk score {risk_score:.1f}")
    if status:
        parts.append(f"status {status}")
    if scan_count:
        parts.append(f"scan count {scan_count}")

    if us["hasSuspiciousTld"]:
        parts.append("suspicious TLD detected")
    if us["hasIpAddress"]:
        parts.append("IP address in domain")
    if us["containsEncodedChars"]:
        parts.append("encoded characters detected")
    if us["subdomainCount"] > 1:
        parts.append(f"{us['subdomainCount']} subdomains")

    parts.append(f"DNS {dns}")

    # ── Enriched features for better vector embeddings ───────────────
    dga = features.get("dgaAnalysis")
    if dga:
        parts.append(f"DGA score {dga['dgaScore']:.2f}")
        if dga["isDGA"]:
            parts.append("domain generation algorithm detected")
        parts.append(f"consonant ratio {dga['consonantRatio']:.2f}")
        parts.append(f"bigram legitimacy {dga['bigramLegitimacy']:.2f}")

    homoglyph = features.get("homoglyphAnalysis")
    if homoglyph and homoglyph["hasHomoglyphs"]:
        parts.append("homoglyph attack detected")
        if homoglyph.get("targetDomain"):
            parts.append(f"impersonating {homoglyph['targetDomain']}")

    tld_risk = features.get("tldRisk")
    if tld_risk:
        parts.append(f"TLD risk {tld_risk['tldRisk']}")

    structural = features.get("structuralAnalysis")
    if structural and structural["bypassTechniques"]:
        parts.append(f"bypass techniques: {', '.join(structural['bypassTechniques'])}")

    brand = features.get("brandImpersonation")
    if brand and not brand.get("is_exact_match") and 0 < brand.get("edit_distance", 999) <= 3:
        parts.append(f"brand impersonation detected edit distance {brand['edit_distance']} from {brand['known_domain']} ({brand['closest_brand']})")

    semantic = features.get("semanticFeatures")
    if semantic:
        parts.append(f"ASN reputation {semantic['asnReputation']:.2f}")

    payload_types = features.get("payloadTypes")
    if payload_types:
        parts.append(f"payload types: {', '.join(payload_types)}")

    query_params = features.get("queryParams")
    if query_params:
        parts.append(f"query parameters: {', '.join(query_params.keys())}")

    parts.append(f"full URL {url}")

    return ", ".join(parts)


def build_threat_intel_text(entry: dict) -> str:
    """Build a composite text from ALL threat intel feed fields for embedding.

    This text is stored as summaryText on the document and used to generate
    the embedding vector, so vector search captures all document signals.
    Richer text = stronger embeddings = better semantic matching.
    """
    parts = [
        entry.get("description", ""),
        f"URL {entry.get('url', '')}",
        f"domain {entry.get('domain', '')}",
        f"feed {entry.get('feedName', '')}",
        f"threat classification {entry.get('threatClassification', entry.get('threatType', ''))}",
    ]
    if entry.get("attackCategory"):
        parts.append(f"attack category {entry['attackCategory']}")
    if entry.get("targetDomain"):
        parts.append(f"target domain {entry['targetDomain']}")
    if entry.get("payloadSignature"):
        parts.append(f"payload signature {entry['payloadSignature']}")
    if entry.get("severity"):
        parts.append(f"severity {entry['severity']}")
    if entry.get("confidence"):
        parts.append(f"confidence {entry['confidence']:.2f}")
    if entry.get("iocType"):
        parts.append(f"IOC type {entry['iocType']}")
    if entry.get("ttl"):
        parts.append(f"TTL {entry['ttl']} days")
    if entry.get("reportedDate"):
        parts.append(f"reported {entry['reportedDate']}")

    # ── Structural/hosting details for richer embedding context ──────
    hf = entry.get("hostingFlags", {})
    if hf:
        if not hf.get("sslValid"):
            parts.append("no valid SSL certificate")
        if hf.get("isSharedHosting"):
            parts.append("shared hosting infrastructure")
        if hf.get("hostingProvider") and hf["hostingProvider"] != "unknown":
            parts.append(f"hosted on {hf['hostingProvider']}")
        if hf.get("geoLocation") and hf["geoLocation"] != "unknown":
            parts.append(f"geo location {hf['geoLocation']}")

    us = entry.get("urlStructure", {})
    if us:
        if us.get("containsEncodedChars"):
            parts.append("contains encoded characters obfuscation")
        if us.get("hasSuspiciousTld"):
            parts.append("suspicious top level domain")
        if us.get("hasIpAddress"):
            parts.append("IP address used instead of domain name")

    # ── Attack technique narrative for semantic richness ──────────────
    _ATTACK_NARRATIVES = {
        "xss": "cross-site scripting attack stealing cookies and session tokens via injected JavaScript",
        "sqli": "SQL injection attack extracting database credentials and sensitive records",
        "path_traversal": "directory traversal attack accessing system files outside web root",
        "command_injection": "operating system command injection for remote code execution and reverse shell",
        "open_redirect": "open redirect abused to send victims to phishing credential harvesting pages",
        "ssrf": "server-side request forgery probing internal network and cloud metadata endpoints",
        "obfuscated_path": "obfuscated URL path bypassing web application firewall rules",
        "base64_payload": "base64 encoded malicious payload evading detection filters",
        "credential_harvest": "credential harvesting form exfiltrating login passwords to attacker server",
        "malware_download": "malicious executable download disguised as legitimate document or update",
        "typosquat_subdomain": "typosquatting subdomain impersonating trusted government domain",
        "dns_tunneling": "DNS tunneling exfiltrating data through encoded DNS queries to attacker nameserver",
        "cryptomining": "cryptomining script injected to hijack visitor CPU for cryptocurrency mining",
        "api_abuse": "API endpoint abuse extracting sensitive data through unauthorized access",
        "supply_chain": "supply chain attack compromising trusted package or dependency with backdoor",
        "watering_hole": "watering hole attack compromising frequently visited site to target specific users",
    }
    cat = entry.get("attackCategory", "")
    if cat in _ATTACK_NARRATIVES:
        parts.append(_ATTACK_NARRATIVES[cat])

    payload_types = entry.get("payloadTypes", [])
    if payload_types:
        parts.append(f"detected payload types: {', '.join(payload_types)}")

    return ", ".join(parts)


def calculate_risk_score(
    features: dict, max_similarity: float = 0.0,
    weights: dict | None = None, url: str = "",
    hard_floors: dict | None = None,
    phishing_keywords: list | None = None,
    intel_match_count: int = 0,
    max_intel_similarity: float = 0.0,
) -> tuple[float, list[dict]]:
    """Calculate risk score using weighted formula with DGA + homoglyph + structural features.

    Returns (score, breakdown) where breakdown is a list of factor contribution dicts.
    """
    if weights is None:
        weights = {
            "domainAge": 0.10,
            "ssl": 0.03,
            "entropy": 0.05,
            "dns": 0.05,
            "hosting": 0.03,
            "vectorSimilarity": 0.15,
            "dgaScore": 0.08,
            "structuralScore": 0.10,
            "homoglyphScore": 0.08,
            "brandImpersonation": 0.15,
            "payloadRisk": 0.18,
        }

    hf = features["hostingFlags"]
    us = features["urlStructure"]
    dns = features["dnsStatus"]

    # Domain age score (younger = riskier) — granular tiers
    age = hf["domainAgeDays"]
    if age < 7:
        domain_age_score = 1.0      # less than a week — very suspicious
    elif age < 30:
        domain_age_score = 0.9      # less than a month
    elif age < 90:
        domain_age_score = 0.7      # less than 3 months
    elif age < 180:
        domain_age_score = 0.5      # less than 6 months
    elif age < 365:
        domain_age_score = 0.3      # less than a year
    elif age < 730:
        domain_age_score = 0.15     # 1-2 years
    else:
        domain_age_score = 0.05     # 2+ years — well-established

    # SSL score
    ssl_score = 0.0 if hf["sslValid"] else 1.0

    # Entropy score (higher entropy = riskier)
    entropy = us["entropyScore"]
    if entropy > 4.5:
        entropy_score = 1.0
    elif entropy > 3.5:
        entropy_score = 0.6
    elif entropy > 2.5:
        entropy_score = 0.3
    else:
        entropy_score = 0.1

    # DNS score
    dns_scores = {"active": 0.2, "inactive": 0.5, "suspended": 0.9, "parked": 0.7}
    dns_score = dns_scores.get(dns, 0.5)

    # Hosting score
    hosting_score = 0.0
    if hf["isSharedHosting"]:
        hosting_score += 0.3
    if not hf["isCloudHosted"]:
        hosting_score += 0.2
    if us["hasSuspiciousTld"]:
        hosting_score += 0.3
    if us["hasIpAddress"]:
        hosting_score += 0.2
    hosting_score = min(hosting_score, 1.0)

    # DGA score
    dga = features.get("dgaAnalysis")
    dga_risk = dga["dgaScore"] if dga else 0.0

    # Structural / bypass score
    structural = features.get("structuralAnalysis")
    structural_risk = structural["structuralScore"] if structural else 0.0

    # Homoglyph / visual impersonation score
    homoglyph = features.get("homoglyphAnalysis")
    homoglyph_risk = homoglyph["visualSimilarity"] if homoglyph and homoglyph.get("hasHomoglyphs") else 0.0

    # Brand impersonation score (Levenshtein distance)
    brand = features.get("brandImpersonation")
    if brand and not brand.get("is_exact_match") and 0 < brand.get("edit_distance", 999) <= 3:
        # Closer edit distance = higher risk: dist 1 → 1.0, dist 2 → 0.7, dist 3 → 0.4
        brand_risk = {1: 1.0, 2: 0.7, 3: 0.4}.get(brand["edit_distance"], 0.0)
    else:
        brand_risk = 0.0

    # Payload risk — detected attack payloads (XSS, SQLi, SSRF, etc.)
    # This captures payloads that structural analysis may miss
    payload_types = features.get("payloadTypes", [])
    _CRITICAL_PAYLOADS = {"command_injection", "ssrf", "sqli"}
    _HIGH_PAYLOADS = {"xss", "path_traversal", "credential_harvest", "malware_download"}
    _MEDIUM_PAYLOADS = {"base64_payload", "obfuscated_path", "dns_tunneling", "dns_exfiltration"}
    if payload_types:
        max_payload = 0.0
        for pt in payload_types:
            if pt in _CRITICAL_PAYLOADS:
                max_payload = max(max_payload, 1.0)
            elif pt in _HIGH_PAYLOADS:
                max_payload = max(max_payload, 0.85)
            elif pt in _MEDIUM_PAYLOADS:
                max_payload = max(max_payload, 0.6)
            else:
                max_payload = max(max_payload, 0.4)
        payload_risk = max_payload
    else:
        payload_risk = 0.0

    # Suspicious keyword bonus — phishing keywords in domain or path
    # amplify risk when combined with other signals
    _PHISHING_KEYWORDS = set(phishing_keywords) if phishing_keywords else {
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "auth",
        "portal", "validate", "suspend", "unlock", "otp", "kyc",
    }
    url_lower = url.lower() if url else features.get("domain", "").lower()
    domain_lower = features["domain"].lower()
    keyword_hits = [kw for kw in _PHISHING_KEYWORDS if kw in domain_lower or kw in url_lower]
    # Each keyword adds up to 0.15 risk, capped at 0.5
    keyword_bonus = min(len(keyword_hits) * 0.15, 0.5)

    # Build breakdown of each factor's weighted contribution
    factors = [
        {"factor": "Domain Age", "key": "domainAge", "raw": round(domain_age_score, 3), "weight": weights["domainAge"], "contribution": round(weights["domainAge"] * domain_age_score * 100, 1)},
        {"factor": "SSL Certificate", "key": "ssl", "raw": round(ssl_score, 3), "weight": weights["ssl"], "contribution": round(weights["ssl"] * ssl_score * 100, 1)},
        {"factor": "URL Entropy", "key": "entropy", "raw": round(entropy_score, 3), "weight": weights["entropy"], "contribution": round(weights["entropy"] * entropy_score * 100, 1)},
        {"factor": "DNS Status", "key": "dns", "raw": round(dns_score, 3), "weight": weights["dns"], "contribution": round(weights["dns"] * dns_score * 100, 1)},
        {"factor": "Hosting Risk", "key": "hosting", "raw": round(hosting_score, 3), "weight": weights["hosting"], "contribution": round(weights["hosting"] * hosting_score * 100, 1)},
        {"factor": "Vector Similarity", "key": "vectorSimilarity", "raw": round(max_similarity, 3), "weight": weights["vectorSimilarity"], "contribution": round(weights["vectorSimilarity"] * max_similarity * 100, 1)},
        {"factor": "DGA Score", "key": "dgaScore", "raw": round(dga_risk, 3), "weight": weights["dgaScore"], "contribution": round(weights["dgaScore"] * dga_risk * 100, 1)},
        {"factor": "Structural Bypass", "key": "structuralScore", "raw": round(structural_risk, 3), "weight": weights["structuralScore"], "contribution": round(weights["structuralScore"] * structural_risk * 100, 1)},
        {"factor": "Homoglyph", "key": "homoglyphScore", "raw": round(homoglyph_risk, 3), "weight": weights.get("homoglyphScore", 0), "contribution": round(weights.get("homoglyphScore", 0) * homoglyph_risk * 100, 1)},
        {"factor": "Brand Impersonation", "key": "brandImpersonation", "raw": round(brand_risk, 3), "weight": weights.get("brandImpersonation", 0), "contribution": round(weights.get("brandImpersonation", 0) * brand_risk * 100, 1)},
        {"factor": "Payload Risk", "key": "payloadRisk", "raw": round(payload_risk, 3), "weight": weights.get("payloadRisk", 0), "contribution": round(weights.get("payloadRisk", 0) * payload_risk * 100, 1)},
    ]

    risk = sum(f["contribution"] for f in factors)

    # Keyword bonus: add raw points for phishing keywords in URL
    keyword_points = round(keyword_bonus * 100, 1)
    risk += keyword_points
    if keyword_points > 0:
        factors.append({"factor": "Phishing Keywords", "key": "keywordBonus", "raw": round(keyword_bonus, 3), "weight": 1.0, "contribution": keyword_points})

    # ── Vector Intel Boost ───────────────────────────────────────────
    # When the scanned URL matches threat intel entries with high cosine
    # similarity, add bonus risk points that scale with match quality.
    # This amplifies the vector AI signal beyond the base 18% weight.
    intel_boost = 0.0
    if intel_match_count > 0 and max_intel_similarity > 0.75:
        # Tier 1: very high similarity (>0.92) — strong match to known threat
        if max_intel_similarity >= 0.92:
            intel_boost = 12.0 + min(intel_match_count - 1, 4) * 2.0
        # Tier 2: high similarity (>0.85) — likely related threat pattern
        elif max_intel_similarity >= 0.85:
            intel_boost = 8.0 + min(intel_match_count - 1, 4) * 1.5
        # Tier 3: moderate similarity (>0.75) — possible threat correlation
        else:
            intel_boost = 4.0 + min(intel_match_count - 1, 4) * 1.0
    intel_boost = round(intel_boost, 1)
    if intel_boost > 0:
        risk += intel_boost
        factors.append({
            "factor": "Vector Intel Boost",
            "key": "vectorIntelBoost",
            "raw": round(max_intel_similarity, 3),
            "weight": 1.0,
            "contribution": intel_boost,
            "intelMatches": intel_match_count,
        })

    # Hard floor: confirmed homoglyph impersonation of a known domain
    # must never score below configured floor regardless of other benign signals
    hf_map = hard_floors or {}
    if homoglyph and homoglyph.get("hasHomoglyphs") and homoglyph.get("visualSimilarity", 0) >= 0.6:
        risk = max(risk, float(hf_map.get("homoglyphVisualSimilarity", 75)))

    # Hard floor: young domain (<30 days) combined with other threat signals
    if age < 30:
        threat_signals = sum([
            bool(payload_types),          # has attack payloads
            bool(keyword_hits),           # has phishing keywords
            not hf["sslValid"],           # no SSL
            us.get("hasSuspiciousTld", False),  # suspicious TLD
            homoglyph_risk > 0,           # homoglyph detected
            brand_risk > 0,               # brand impersonation
        ])
        if age < 7 and threat_signals >= 1:
            risk = max(risk, float(hf_map.get("youngDomain7d", 65)))
        elif age < 30 and threat_signals >= 2:
            risk = max(risk, float(hf_map.get("youngDomain30d", 55)))

    # Hard floor: brand impersonation (typosquat) of a known government domain
    if brand and not brand.get("is_exact_match"):
        dist = brand.get("edit_distance", 999)
        if dist == 1:
            risk = max(risk, float(hf_map.get("brandDist1", 78)))
            if keyword_hits:
                risk = max(risk, float(hf_map.get("brandDist1WithKeywords", 85)))
        elif dist == 2:
            risk = max(risk, float(hf_map.get("brandDist2", 60)))
            if keyword_hits:
                risk = max(risk, float(hf_map.get("brandDist2WithKeywords", 72)))
        elif dist == 3:
            if keyword_hits:
                risk = max(risk, float(hf_map.get("brandDist3WithKeywords", 55)))

    return round(min(risk, 100.0), 1), factors


def classify_threat(risk_score: float, thresholds: dict | None = None) -> str:
    t = thresholds or {}
    if risk_score >= t.get("classifyPhishing", 80):
        return "phishing"
    elif risk_score >= t.get("classifyMalware", 60):
        return "malware"
    elif risk_score >= t.get("classifySuspicious", 40):
        return "suspicious"
    else:
        return "benign"


def risk_level(score: float, thresholds: dict | None = None) -> str:
    t = thresholds or {}
    if score >= t.get("classifyPhishing", 80):
        return "critical"
    elif score >= t.get("classifyMalware", 60):
        return "high"
    elif score >= t.get("classifySuspicious", 40):
        return "medium"
    else:
        return "low"


def recommended_action(score: float, thresholds: dict | None = None) -> str:
    t = thresholds or {}
    if score >= t.get("blockScore", 75):
        return "block"
    elif score >= t.get("reviewScore", 50):
        return "review"
    else:
        return "allow"
