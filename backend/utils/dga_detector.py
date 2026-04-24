"""DGA (Domain Generation Algorithm) and advanced semantic threat detection.

Detects algorithmically-generated domains (Suppobox, Mirai, Necurs-style)
using structural heuristics that catch zero-day URLs missed by blacklists.

Implements the five Semantic Features for vector embedding:
  1. Visual similarity — homoglyph / typosquat detection
  2. TLD entropy — top-level domain risk scoring
  3. Consonant ratio — DGA bigram frequency analysis
  4. Domain tokenization — structural pattern decomposition
  5. ASN/hosting reputation — infrastructure risk signal
"""

import math
import re
import logging
from collections import Counter

logger = logging.getLogger(__name__)

# ── Homoglyph map — visually similar characters used in phishing ──────────
HOMOGLYPH_MAP: dict[str, str] = {
    "0": "o", "1": "l", "!": "l", "|": "l",
    "rn": "m", "vv": "w", "cl": "d",
    "а": "a", "е": "e", "о": "o", "р": "p",  # Cyrillic look-alikes
    "с": "c", "у": "y", "х": "x",
}

LEGITIMATE_GOV_DOMAINS = {
    "nic.in", "gov.in", "india.gov.in", "cert-in.org.in",
    "digitalindia.gov.in", "data.gov.in", "mygov.in",
    "incometax.gov.in", "uidai.gov.in", "passportindia.gov.in",
    "epfindia.gov.in", "nsdl.co.in", "irctc.co.in",
}

# Global brands frequently targeted by phishing/typosquatting
GLOBAL_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "paypal.com", "netflix.com", "linkedin.com",
    "dropbox.com", "outlook.com", "instagram.com", "twitter.com",
    "whatsapp.com", "telegram.org", "github.com", "zoom.us",
    "office.com", "live.com", "yahoo.com", "gmail.com",
}

# Combined set for homoglyph detection
_ALL_PROTECTED_DOMAINS = LEGITIMATE_GOV_DOMAINS | GLOBAL_BRAND_DOMAINS

# Common English bigrams (high frequency = legitimate)
ENGLISH_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
}

# TLD risk tiers
TLD_RISK_HIGH = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".icu", ".cam", ".monster", ".rest", ".fit", ".work", ".club"}
TLD_RISK_MEDIUM = {".info", ".biz", ".online", ".site", ".pw", ".cc", ".ws", ".to", ".link", ".click", ".stream"}
TLD_RISK_LOW = {".com", ".org", ".net", ".edu", ".gov", ".mil", ".in", ".co.in", ".gov.in", ".org.in", ".ac.in"}


def detect_dga(domain: str) -> dict:
    """Detect Domain Generation Algorithm patterns.

    Returns a dict with:
      - isDGA (bool): whether the domain exhibits DGA characteristics
      - dgaScore (float 0-1): confidence that this is machine-generated
      - dgaSignals (list[str]): human-readable explanations
      - consonantRatio (float): ratio of consonants to total alpha chars
      - bigramLegitimacy (float 0-1): how many bigrams match English
      - domainLength (int): length of the second-level domain
    """
    # Extract the second-level domain label (e.g. "abc123xyz" from "abc123xyz.evil.com")
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        sld = parts[-2] if parts[-1] not in ("in", "uk", "au", "za") else (
            parts[-3] if len(parts) >= 3 else parts[0]
        )
    else:
        sld = parts[0]

    signals: list[str] = []
    score_components: list[float] = []

    # ── 1. Consonant-to-vowel ratio ──────────────────────────────────────
    vowels = set("aeiou")
    alpha_chars = [c for c in sld if c.isalpha()]
    if alpha_chars:
        consonant_count = sum(1 for c in alpha_chars if c not in vowels)
        consonant_ratio = consonant_count / len(alpha_chars)
    else:
        consonant_ratio = 0.5

    if consonant_ratio > 0.75:
        signals.append(f"Abnormal consonant ratio ({consonant_ratio:.2f}) — typical of DGA domains like Suppobox/Mirai")
        score_components.append(0.9)
    elif consonant_ratio > 0.65:
        signals.append(f"Elevated consonant ratio ({consonant_ratio:.2f}) — possibly algorithmic")
        score_components.append(0.5)
    else:
        score_components.append(0.1)

    # ── 2. Bigram analysis — English language legitimacy ─────────────────
    if len(sld) >= 2:
        bigrams = [sld[i:i+2] for i in range(len(sld) - 1) if sld[i:i+2].isalpha()]
        if bigrams:
            english_hits = sum(1 for bg in bigrams if bg in ENGLISH_BIGRAMS)
            bigram_legitimacy = english_hits / len(bigrams)
        else:
            bigram_legitimacy = 0.0
    else:
        bigram_legitimacy = 0.5

    if bigram_legitimacy < 0.15:
        signals.append(f"Very low English bigram frequency ({bigram_legitimacy:.2f}) — random character sequences")
        score_components.append(0.9)
    elif bigram_legitimacy < 0.30:
        signals.append(f"Low English bigram frequency ({bigram_legitimacy:.2f}) — uncommon character patterns")
        score_components.append(0.5)
    else:
        score_components.append(0.1)

    # ── 3. Digit-alpha mixing ────────────────────────────────────────────
    digits = sum(1 for c in sld if c.isdigit())
    alpha = sum(1 for c in sld if c.isalpha())
    if alpha > 0 and digits > 0:
        digit_ratio = digits / (digits + alpha)
        if digit_ratio > 0.3:
            signals.append(f"Heavy digit-alpha mixing ({digits}d/{alpha}a) — DGA domains interleave numbers")
            score_components.append(0.7)
        else:
            score_components.append(0.2)
    else:
        score_components.append(0.1)

    # ── 4. Domain length anomaly ─────────────────────────────────────────
    domain_length = len(sld)
    if domain_length > 20:
        signals.append(f"Unusually long domain label ({domain_length} chars) — DGA output often exceeds 20 chars")
        score_components.append(0.8)
    elif domain_length > 14:
        signals.append(f"Long domain label ({domain_length} chars) — above average for legitimate domains")
        score_components.append(0.4)
    else:
        score_components.append(0.1)

    # ── 5. Entropy of the SLD ────────────────────────────────────────────
    sld_entropy = _char_entropy(sld)
    if sld_entropy > 3.8:
        signals.append(f"High domain entropy ({sld_entropy:.2f}) — random-looking character distribution")
        score_components.append(0.8)
    elif sld_entropy > 3.2:
        score_components.append(0.4)
    else:
        score_components.append(0.1)

    # ── Aggregate DGA score ──────────────────────────────────────────────
    dga_score = sum(score_components) / len(score_components) if score_components else 0.0
    dga_score = round(min(dga_score, 1.0), 3)

    return {
        "isDGA": dga_score >= 0.50,
        "dgaScore": dga_score,
        "dgaSignals": signals,
        "consonantRatio": round(consonant_ratio, 3),
        "bigramLegitimacy": round(bigram_legitimacy, 3),
        "domainLength": domain_length,
        "sldEntropy": round(sld_entropy, 2),
    }


def detect_homoglyphs(domain: str) -> dict:
    """Detect visual-similarity / typosquat attacks against known gov domains.

    Returns:
      - hasHomoglyphs (bool): visual tricks detected
      - homoglyphSignals (list[str]): explanations
      - targetDomain (str|None): the legitimate domain being impersonated
      - visualSimilarity (float 0-1): how close it is to a known domain
    """
    signals: list[str] = []
    clean = domain.lower()

    # Check for Cyrillic/Unicode confusables
    non_ascii = [c for c in clean if ord(c) > 127]
    if non_ascii:
        signals.append(
            f"Contains non-ASCII characters ({len(non_ascii)} chars) — "
            "possible IDN homoglyph attack (Cyrillic/Unicode look-alikes)"
        )

    # Normalize confusables
    normalized = clean
    for fake, real in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)

    # Compare against known legitimate domains (gov + global brands)
    best_target = None
    best_similarity = 0.0
    for legit in _ALL_PROTECTED_DOMAINS:
        sim = _domain_similarity(normalized, legit)
        if sim > best_similarity:
            best_similarity = sim
            best_target = legit

    # If the domain IS a known legitimate domain (no confusable normalization
    # needed), skip all homoglyph checks.  Only skip when the raw domain AND
    # its normalized form both land in the allow-list — i.e. the domain is
    # genuinely legitimate, not a confusable variant like g0v.in → gov.in.
    if clean in _ALL_PROTECTED_DOMAINS and normalized == clean:
        return {
            "hasHomoglyphs": False,
            "homoglyphSignals": [],
            "targetDomain": clean,
            "visualSimilarity": 1.0,
        }

    # If normalizing confusables maps to a legitimate domain, that's an attack
    if normalized != clean and normalized in _ALL_PROTECTED_DOMAINS:
        signals.append(
            f"Visually impersonates '{normalized}' via confusable characters "
            f"(e.g. 0→o, 1→l, Cyrillic) — likely homoglyph/typosquat attack"
        )
        best_target = normalized
        best_similarity = 0.95  # high confidence since normalization matched exactly

    if best_similarity > 0.85 and best_similarity < 1.0:
        signals.append(
            f"Visually similar to legitimate domain '{best_target}' "
            f"({best_similarity*100:.0f}% similarity) — likely typosquat/homoglyph attack"
        )
    elif best_similarity > 0.70 and best_similarity < 1.0:
        signals.append(
            f"Moderate visual similarity to '{best_target}' "
            f"({best_similarity*100:.0f}%) — possible impersonation attempt"
        )

    # Check for common typosquat patterns
    typo_patterns = [
        (r"g0v|gov\d|g[oO0]v", "Letter-digit substitution in 'gov'"),
        (r"n[i1!|]c|n[lI]c", "Visual trick in 'nic' (1/l/I substitution)"),
        (r"-+", None),  # skip hyphens
    ]
    for pattern, desc in typo_patterns:
        if desc and re.search(pattern, clean):
            signals.append(f"{desc} — common phishing technique")

    return {
        "hasHomoglyphs": len(signals) > 0,
        "homoglyphSignals": signals,
        "targetDomain": best_target if best_similarity > 0.70 else None,
        "visualSimilarity": round(best_similarity, 3),
    }


def compute_tld_risk(domain: str) -> dict:
    """Score TLD reputation risk.

    Returns:
      - tldRisk (str): high/medium/low
      - tldScore (float 0-1): risk score
      - tldNote (str): explanation
    """
    tld = "." + domain.lower().split(".")[-1]

    if tld in TLD_RISK_HIGH:
        return {"tldRisk": "high", "tldScore": 0.9, "tldNote": f"TLD '{tld}' is frequently abused for malicious domains"}
    elif tld in TLD_RISK_MEDIUM:
        return {"tldRisk": "medium", "tldScore": 0.5, "tldNote": f"TLD '{tld}' has moderate abuse rates"}
    else:
        return {"tldRisk": "low", "tldScore": 0.1, "tldNote": f"TLD '{tld}' is generally trusted"}


def compute_structural_threat_score(url: str, domain: str) -> dict:
    """Compute structural / behavioral threat signals from URL patterns.

    These catch threats that bypass regex/rule-based systems because
    the individual tokens look benign but the *structure* is suspicious.

    Returns:
      - structuralScore (float 0-1)
      - structuralSignals (list[str])
      - bypassTechniques (list[str]): specific bypass methods detected
    """
    signals: list[str] = []
    bypasses: list[str] = []
    scores: list[float] = []

    lower = url.lower()

    # ── Path traversal ───────────────────────────────────────────────────
    if ".." in url or "%2e%2e" in lower:
        signals.append("Path traversal sequences detected (../ or encoded %2e%2e)")
        bypasses.append("path_traversal")
        scores.append(0.9)

    # ── Encoded payload ──────────────────────────────────────────────────
    encoded_patterns = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(encoded_patterns) > 5:
        signals.append(f"Heavy URL encoding ({len(encoded_patterns)} encoded chars) — payload obfuscation")
        bypasses.append("encoding_obfuscation")
        scores.append(0.8)

    # ── Base64 in URL ────────────────────────────────────────────────────
    b64_match = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", url)
    if b64_match:
        signals.append("Possible Base64-encoded payload in URL path/parameters")
        bypasses.append("base64_payload")
        scores.append(0.7)

    # ── Redirect chains ──────────────────────────────────────────────────
    redirect_indicators = sum(1 for kw in ["redirect", "url=", "next=", "goto=", "return=", "redir=", "dest="] if kw in lower)
    if redirect_indicators >= 1:
        signals.append(f"Open redirect indicators found ({redirect_indicators} redirect parameters)")
        bypasses.append("open_redirect")
        scores.append(0.7)

    # ── Suspicious query patterns ────────────────────────────────────────
    if re.search(r"(cmd|exec|system|eval|wget|curl|bash)\s*=", lower):
        signals.append("Command injection keywords in query parameters")
        bypasses.append("command_injection")
        scores.append(0.95)

    if re.search(r"(<script|javascript:|on\w+=)", lower):
        signals.append("XSS payload patterns detected in URL")
        bypasses.append("xss_payload")
        scores.append(0.9)

    if re.search(r"(union\s+select|or\s+1\s*=\s*1|drop\s+table)", lower):
        signals.append("SQL injection patterns detected in URL")
        bypasses.append("sql_injection")
        scores.append(0.95)

    # ── Excessive subdomains (DNS tunneling / C2) ────────────────────────
    subdomain_count = len(domain.split(".")) - 2
    if subdomain_count > 3:
        signals.append(f"Excessive subdomains ({subdomain_count}) — possible DNS tunneling or C2 beaconing")
        bypasses.append("dns_tunneling")
        scores.append(0.7)

    # ── Data exfiltration via long hostnames ──────────────────────────────
    if len(domain) > 60:
        signals.append(f"Unusually long hostname ({len(domain)} chars) — possible data exfiltration via DNS")
        bypasses.append("dns_exfiltration")
        scores.append(0.8)

    structural_score = max(scores) if scores else 0.0

    return {
        "structuralScore": round(structural_score, 3),
        "structuralSignals": signals,
        "bypassTechniques": bypasses,
    }


def build_semantic_features(url: str, features: dict, dga: dict, homoglyph: dict, tld_risk: dict, structural: dict) -> dict:
    """Combine all semantic feature dimensions into a single feature set.

    The five core Semantic Features for the vector embedding:
      1. visualSimilarity — homoglyph / typosquat score
      2. tldEntropy — TLD risk score
      3. consonantRatio — DGA indicator via character composition
      4. domainTokenization — structural decomposition score
      5. asnReputation — hosting/infrastructure risk signal
    """
    hf = features["hostingFlags"]

    # ASN reputation score (simulated from hosting features)
    asn_score = 0.0
    if hf["isSharedHosting"]:
        asn_score += 0.3
    if hf["hostingProvider"] in ("unknown-host-provider",):
        asn_score += 0.3
    if hf["geoLocation"] in ("RU", "CN", "UA", "RO"):
        asn_score += 0.2
    if not hf["sslValid"]:
        asn_score += 0.2
    asn_score = min(asn_score, 1.0)

    return {
        "visualSimilarity": homoglyph["visualSimilarity"],
        "tldEntropy": tld_risk["tldScore"],
        "consonantRatio": dga["consonantRatio"],
        "domainTokenization": structural["structuralScore"],
        "asnReputation": round(asn_score, 3),
        "dgaScore": dga["dgaScore"],
        "bigramLegitimacy": dga["bigramLegitimacy"],
    }


# ── Private helpers ──────────────────────────────────────────────────────

def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _domain_similarity(a: str, b: str) -> float:
    """Simple character-level Jaccard + positional similarity."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0

    # Character bigram Jaccard
    a_bigrams = set(a[i:i+2] for i in range(len(a) - 1))
    b_bigrams = set(b[i:i+2] for i in range(len(b) - 1))
    if not a_bigrams or not b_bigrams:
        return 0.0

    intersection = len(a_bigrams & b_bigrams)
    union = len(a_bigrams | b_bigrams)
    return intersection / union if union > 0 else 0.0
