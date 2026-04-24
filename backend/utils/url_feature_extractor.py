"""URL feature extraction and analysis utilities."""

import math
import re
import logging
from urllib.parse import urlparse, unquote
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

    # Simulate dynamic features (in production these would come from real lookups)
    domain_age_days = random.randint(1, 3650)
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
    }


def enrich_features(url: str, base_features: dict) -> dict:
    """Run advanced detectors (DGA, homoglyph, TLD, structural) on top of base features.

    Returns the base features dict augmented with:
      - dgaAnalysis, homoglyphAnalysis, tldRisk, structuralAnalysis, semanticFeatures
    """
    domain = base_features["domain"]

    dga = detect_dga(domain)
    homoglyph = detect_homoglyphs(domain)
    tld_risk = compute_tld_risk(domain)
    structural = compute_structural_threat_score(url, domain)
    semantic = build_semantic_features(url, base_features, dga, homoglyph, tld_risk, structural)

    # Brand impersonation (Levenshtein distance against known gov domains)
    brand = detect_brand_impersonation(domain)
    brand_dict = brand.model_dump()

    base_features["dgaAnalysis"] = dga
    base_features["homoglyphAnalysis"] = homoglyph
    base_features["tldRisk"] = tld_risk
    base_features["structuralAnalysis"] = structural
    base_features["semanticFeatures"] = semantic
    base_features["brandImpersonation"] = brand_dict

    return base_features


def build_summary_text(url: str, features: dict) -> str:
    """Build a natural language summary from extracted features.

    Fuses both textual URL info and non-textual metadata (TTL, IP count,
    SSL, DGA score) into a single text for embedding generation.
    This allows the vector space to capture multi-modal signals.
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

    return ", ".join(parts)


def calculate_risk_score(features: dict, max_similarity: float = 0.0, weights: dict | None = None, url: str = "") -> float:
    """Calculate risk score using weighted formula with DGA + homoglyph + structural features."""
    if weights is None:
        weights = {
            "domainAge": 0.06,
            "ssl": 0.06,
            "entropy": 0.06,
            "dns": 0.06,
            "hosting": 0.06,
            "vectorSimilarity": 0.16,
            "dgaScore": 0.12,
            "structuralScore": 0.12,
            "homoglyphScore": 0.12,
            "brandImpersonation": 0.18,
        }

    hf = features["hostingFlags"]
    us = features["urlStructure"]
    dns = features["dnsStatus"]

    # Domain age score (younger = riskier)
    age = hf["domainAgeDays"]
    if age < 30:
        domain_age_score = 1.0
    elif age < 180:
        domain_age_score = 0.7
    elif age < 365:
        domain_age_score = 0.4
    else:
        domain_age_score = 0.1

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

    # Suspicious keyword bonus — phishing keywords in domain or path
    # amplify risk when combined with other signals
    _PHISHING_KEYWORDS = {
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "auth",
        "portal", "validate", "suspend", "unlock", "otp", "kyc",
    }
    url_lower = url.lower() if url else features.get("domain", "").lower()
    domain_lower = features["domain"].lower()
    keyword_hits = [kw for kw in _PHISHING_KEYWORDS if kw in domain_lower or kw in url_lower]
    # Each keyword adds up to 0.15 risk, capped at 0.5
    keyword_bonus = min(len(keyword_hits) * 0.15, 0.5)

    risk = (
        weights["domainAge"] * domain_age_score
        + weights["ssl"] * ssl_score
        + weights["entropy"] * entropy_score
        + weights["dns"] * dns_score
        + weights["hosting"] * hosting_score
        + weights["vectorSimilarity"] * max_similarity
        + weights["dgaScore"] * dga_risk
        + weights["structuralScore"] * structural_risk
        + weights.get("homoglyphScore", 0) * homoglyph_risk
        + weights.get("brandImpersonation", 0) * brand_risk
    ) * 100

    # Keyword bonus: add raw points for phishing keywords in URL
    risk += keyword_bonus * 100

    # Hard floor: confirmed homoglyph impersonation of a known domain
    # must never score below 75 regardless of other benign signals
    if homoglyph and homoglyph.get("hasHomoglyphs") and homoglyph.get("visualSimilarity", 0) >= 0.6:
        risk = max(risk, 75.0)

    # Hard floor: brand impersonation (typosquat) of a known government domain
    if brand and not brand.get("is_exact_match"):
        dist = brand.get("edit_distance", 999)
        if dist == 1:
            risk = max(risk, 78.0)   # 1 char away → block
            # Brand impersonation + phishing keywords = certain phishing
            if keyword_hits:
                risk = max(risk, 85.0)
        elif dist == 2:
            risk = max(risk, 60.0)   # 2 chars away → high risk review
            if keyword_hits:
                risk = max(risk, 72.0)
        elif dist == 3:
            if keyword_hits:
                risk = max(risk, 55.0)

    return round(min(risk, 100.0), 1)


def classify_threat(risk_score: float) -> str:
    if risk_score >= 80:
        return "phishing"
    elif risk_score >= 60:
        return "malware"
    elif risk_score >= 40:
        return "suspicious"
    else:
        return "benign"


def risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def recommended_action(score: float) -> str:
    if score >= 75:
        return "block"
    elif score >= 50:
        return "review"
    else:
        return "allow"
