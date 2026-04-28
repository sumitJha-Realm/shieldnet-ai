"""
Complete database reset and focused demo seeding script.

This script:
  1. Drops ALL collections (urls, campaigns, threat_logs)
  2. Seeds 1000 URLs across exactly 10 base domains
  3. Generates realistic URL variants for each domain (benign, phishing, malware, c2, suspicious)
  4. Generates Voyage AI vector embeddings for every URL
  5. Creates campaigns in the campaigns collection, linking related threat URLs
  6. Creates Atlas Search index and vector search index on the urls collection

Usage:
    docker compose exec backend poetry run python -m scripts.reset_and_seed

Options:
    --skip-embeddings    Insert without calling Voyage AI (uses zero vectors)
    --total 1000         Total URL records to seed (default: 1000)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import math
import os
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import httpx

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", os.getenv("DATABASE_NAME", "shieldnet-ai"))
VOYAGE_API_KEY = os.getenv("VOYAGE_AI_API_KEY", "")
VOYAGE_MODEL = os.getenv("VOYAGE_MODEL", "voyage-4")
VOYAGE_URL = "https://ai.mongodb.com/v1/embeddings"
EMBED_BATCH_SIZE = 64

# ─────────────────────────────────────────────
# 10 Base Domains — 3 campaigns + 2 standalone
# ─────────────────────────────────────────────
CAMPAIGNS = [
    {
        "campaignId": "campaign_001_tax_auth_2025",
        "name": "Tax Authority Phishing Campaign Q1 2025",
        "attackCategory": "credential_harvest",
        "severity": "critical",
        "threatActor": "APT-IN-TAX-01",
        "domains": ["incometax.gov.in", "gst.gov.in", "pmkisan.gov.in"],
        "target": "Indian tax and subsidy portals",
    },
    {
        "campaignId": "campaign_002_banking_2025",
        "name": "Banking Credential Harvest Campaign Q2 2025",
        "attackCategory": "credential_harvest",
        "severity": "critical",
        "threatActor": "APT-FIN-BANK-07",
        "domains": ["sbi.co.in", "icici.com", "hdfc.com"],
        "target": "Indian retail banking customers",
    },
    {
        "campaignId": "campaign_003_identity_2025",
        "name": "National Identity Document Phishing Campaign 2025",
        "attackCategory": "brand_impersonation",
        "severity": "high",
        "threatActor": "APT-ID-DOC-03",
        "domains": ["aadhaar.gov.in", "passport.gov.in"],
        "target": "UIDAI and MEA document portals",
    },
]

STANDALONE_DOMAINS = [
    {"domain": "certifiedsoftware.in", "label": "benign_standalone"},
    {"domain": "generic-malware-c2.ru", "label": "malware_standalone"},
]

# All 10 domains in one flat lookup
DOMAIN_TO_CAMPAIGN: dict[str, str | None] = {}
for c in CAMPAIGNS:
    for d in c["domains"]:
        DOMAIN_TO_CAMPAIGN[d] = c["campaignId"]
for s in STANDALONE_DOMAINS:
    DOMAIN_TO_CAMPAIGN[s["domain"]] = None

ALL_DOMAINS = list(DOMAIN_TO_CAMPAIGN.keys())  # exactly 10


# ─────────────────────────────────────────────
# URL Variant Templates per domain
# ─────────────────────────────────────────────
BENIGN_PATHS = [
    "/", "/login", "/dashboard", "/services", "/help",
    "/about", "/contact", "/faq", "/forms", "/status",
    "/citizen/profile", "/portal", "/documents", "/verify/otp",
    "/receipts", "/applications", "/track", "/payments/history",
]

PHISHING_PATHS = [
    "/signin", "/auth/verify", "/account/confirm", "/secure/login",
    "/portal/update", "/confirm/identity", "/kyc/verify",
    "/reset-password", "/auth/token", "/sso/callback",
    "/payment/refund", "/claim/benefit", "/verify/aadhaar",
    "/download/form16.exe", "/update/pin",
]

MALWARE_PATHS = [
    "/download/setup.exe", "/update/client.msi", "/download/patch.bat",
    "/api/v1/payload", "/static/helper.exe", "/cdn/update.ps1",
    "/assets/installer.vbs", "/tools/scanner.exe",
]

C2_PATHS = [
    "/api/checkin", "/beacon/report", "/c2/cmd",
    "/heartbeat", "/poll/tasks", "/agent/register",
    "/bot/status", "/command/fetch",
]

SUSPICIOUS_PATHS = [
    "/redirect?next=http://evil.example", "/track?id=admin&payload=base64abc123",
    "/proxy?url=http://malicious.tk", "/redir?target=http://phish.xyz",
    "/search?q=<script>alert(1)</script>", "/api/debug",
    "/.env", "/.git/config", "/wp-admin/",
]

HOMOGLYPH_MAP = {"i": "1", "a": "4", "e": "3", "o": "0", "s": "5", "l": "1"}

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ru", ".top", ".icu", ".buzz", ".cam", ".rest"]


def make_homoglyph(domain: str) -> str:
    """Substitute 1-2 characters with homoglyphs."""
    parts = domain.split(".")
    base = list(parts[0])
    tld = ".".join(parts[1:])
    replaceable = [(i, c) for i, c in enumerate(base) if c in HOMOGLYPH_MAP]
    if replaceable:
        chosen = random.sample(replaceable, min(2, len(replaceable)))
        for idx, ch in chosen:
            base[idx] = HOMOGLYPH_MAP[ch]
    return "".join(base) + "." + tld


def make_fake_alert_domain(domain: str) -> str:
    brand = domain.split(".")[0]
    tld = random.choice(SUSPICIOUS_TLDS)
    prefix = random.choice(["secure-verify", "account-update", "login-confirm", "portal-check", "kyc-verify"])
    return f"{prefix}-{brand}{tld}"


def make_malware_domain(domain: str) -> str:
    brand = domain.replace(".", "-")
    tld = random.choice([".tk", ".xyz", ".top"])
    return f"malware-{brand}-host{tld}"


def make_c2_domain(domain: str) -> str:
    brand = domain.replace(".", "-")
    return f"c2-{brand}-panel.ru"


def make_suspicious_domain(domain: str) -> str:
    brand = domain.split(".")[0]
    suffix = random.choice(["service", "portal", "update", "verify", "support"])
    tld = random.choice(SUSPICIOUS_TLDS)
    return f"{brand}-{suffix}{tld}"


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 2)


def random_when(days_back: int = 90) -> datetime:
    return datetime.utcnow() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


def detect_payload_types(url: str) -> list[str]:
    patterns = {
        "xss": re.compile(r"<script|onerror\s*=|javascript:", re.I),
        "sqli": re.compile(r"'\s*OR|UNION\s+SELECT|DROP\s+TABLE", re.I),
        "path_traversal": re.compile(r"\.\./|%2e%2e|/etc/passwd|\.env|\.git", re.I),
        "command_injection": re.compile(r";\s*cat|;\s*ping|\|\s*wget|&&\s*curl", re.I),
        "open_redirect": re.compile(r"(?:redirect|next|goto|url)\s*=\s*https?://", re.I),
        "ssrf": re.compile(r"169\.254\.169\.254|localhost|127\.0\.0\.1", re.I),
        "malware_download": re.compile(r"\.(exe|msi|bat|cmd|ps1|vbs|jar)(\?|$)", re.I),
        "credential_harvest": re.compile(r"(?:formAction|webhook|postback|notify)\s*=\s*https?://", re.I),
    }
    found = [name for name, pat in patterns.items() if pat.search(url)]
    return found


def build_url_record(
    url: str,
    domain: str,
    base_domain: str,
    threat_class: str,
    variation_type: str,
    campaign_id: str | None,
) -> dict:
    """Build a complete URL document matching the URLRecord schema."""
    is_benign = threat_class == "benign"
    scheme = "https" if is_benign else random.choice(["https", "http"])

    # Risk score ranges by class
    risk_ranges = {
        "benign": (3, 28),
        "suspicious": (45, 65),
        "phishing": (68, 92),
        "malware": (80, 97),
        "c2": (85, 99),
    }
    lo, hi = risk_ranges[threat_class]
    risk = round(random.uniform(lo, hi), 1)
    status = "allowed" if risk < 45 else ("under_review" if risk < 70 else "blocked")

    payload_types = detect_payload_types(url)
    entropy = calculate_entropy(domain)
    domain_age = random.randint(300, 5000) if is_benign else random.randint(1, 180)
    tld = "." + domain.rsplit(".", 1)[-1]
    suspicious_tld = tld in {".xyz", ".tk", ".ru", ".top", ".icu", ".buzz", ".cam", ".rest"}
    has_ip = bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain))
    has_encoded = "%" in url
    path_depth = len([p for p in url.split("/")[3:] if p])
    subdomain_count = max(0, len(domain.split(".")) - 2)

    created = random_when(90)

    hosting_provider = random.choice(["aws", "azure", "gcp", "digitalocean", "cloudflare", "unknown"]) if is_benign else random.choice(["unknown", "digitalocean", "ovh"])
    geo = random.choice(["IN", "SG", "US"]) if is_benign else random.choice(["RU", "NL", "UA", "RO", "CN"])

    dga_score = 0.1 if is_benign else round(random.uniform(3.0, 8.5), 2)
    is_dga = dga_score > 5.0

    summary_parts = [
        f"URL analysis for {domain}",
        f"domain age {domain_age} days",
        f"{'valid' if scheme == 'https' else 'no valid'} SSL",
        f"hosted by {hosting_provider}",
        f"geo {geo}",
        f"entropy {entropy:.2f}",
        f"threat classification {threat_class}",
        f"risk score {risk:.1f}",
        f"status {status}",
        variation_type.replace("_", " "),
    ]
    if campaign_id:
        summary_parts.append(f"part of campaign {campaign_id}")
    if suspicious_tld:
        summary_parts.append("suspicious TLD detected")
    if payload_types:
        summary_parts.extend(payload_types)
    if is_dga:
        summary_parts.append("domain generation algorithm detected")

    summary_text = ". ".join(summary_parts)

    return {
        "url": url,
        "domain": domain,
        "baseDomain": base_domain,
        "canonicalDomain": base_domain,
        "canonicalAuthorityUrl": f"https://{base_domain}/",
        "variationType": variation_type,
        "campaignId": campaign_id,
        "submissionDate": created,
        "source": "demo_reset_seed",
        "demoSeed": True,
        "demoSeedVersion": "focused-v2",
        "dnsStatus": "active" if is_benign else random.choice(["active", "parked", "suspended"]),
        "hostingFlags": {
            "isSharedHosting": not is_benign,
            "isCloudHosted": random.choice([True, False]),
            "hostingProvider": hosting_provider,
            "geoLocation": geo,
            "sslValid": scheme == "https",
            "domainAgeDays": domain_age,
        },
        "urlStructure": {
            "pathDepth": path_depth,
            "hasIpAddress": has_ip,
            "hasSuspiciousTld": suspicious_tld,
            "entropyScore": entropy,
            "containsEncodedChars": has_encoded,
            "subdomainCount": subdomain_count,
        },
        "dgaAnalysis": {
            "isDGA": is_dga,
            "dgaScore": dga_score,
            "dgaSignals": ["high_consonant_ratio", "low_bigram_legitimacy"] if is_dga else [],
            "consonantRatio": round(random.uniform(0.4, 0.7) if is_benign else random.uniform(0.6, 0.9), 3),
            "bigramLegitimacy": round(random.uniform(0.5, 0.9) if is_benign else random.uniform(0.1, 0.5), 3),
            "domainLength": len(domain.split(".")[0]),
            "sldEntropy": round(entropy, 2),
        },
        "homoglyphAnalysis": {
            "hasHomoglyphs": variation_type == "typo",
            "homoglyphSignals": [f"character substitution in {base_domain}"] if variation_type == "typo" else [],
            "targetDomain": base_domain if variation_type == "typo" else None,
            "visualSimilarity": round(random.uniform(0.85, 0.98), 3) if variation_type == "typo" else 1.0,
        },
        "brandImpersonation": {
            "isBrandImpersonation": variation_type in ("typo", "fake_alert"),
            "targetBrand": base_domain.split(".")[0] if variation_type in ("typo", "fake_alert") else None,
            "impersonationScore": round(random.uniform(0.75, 0.97), 3) if variation_type in ("typo", "fake_alert") else 0.0,
        },
        "tldRisk": {
            "tldRisk": "high" if suspicious_tld else "low",
            "tldScore": 0.8 if suspicious_tld else 0.1,
            "tldNote": f"TLD '{tld}' is {'high-risk' if suspicious_tld else 'generally trusted'}",
        },
        "structuralAnalysis": {
            "structuralScore": round(random.uniform(0.5, 0.9), 2) if not is_benign else 0.0,
            "structuralSignals": [] if is_benign else ["phishing_keyword_pattern", "suspicious_subdomain"],
            "bypassTechniques": payload_types[:2] if payload_types else [],
        },
        "semanticFeatures": {
            "phishingKeywords": [] if is_benign else random.sample(
                ["verify", "confirm", "secure", "login", "update", "kyc", "refund", "auth"], 
                k=min(3, 8)
            ),
            "malwareKeywords": ["download", "exe", "installer"] if threat_class in ("malware",) else [],
            "c2Keywords": ["checkin", "beacon", "c2", "panel", "command"] if threat_class == "c2" else [],
        },
        "threatClassification": threat_class,
        "riskScore": risk,
        "status": status,
        "reviewedBy": "system_ai",
        "summaryText": summary_text,
        "payloadTypes": payload_types,
        "queryParams": {},
        "scanCount": random.randint(1, 15),
        "firstSeenAt": created - timedelta(days=random.randint(0, 10)),
        "lastSeenAt": created + timedelta(hours=random.randint(0, 48)),
        "reasons": [f"{variation_type.replace('_', ' ')} detected for {base_domain}"],
        "riskBreakdown": {
            "phishingKeywords": round(random.uniform(0.5, 1.0), 2) if threat_class == "phishing" else 0.0,
            "malwareKeywords": round(random.uniform(0.5, 1.0), 2) if threat_class == "malware" else 0.0,
            "c2Keywords": round(random.uniform(0.5, 1.0), 2) if threat_class == "c2" else 0.0,
            "suspiciousTLD": 0.35 if suspicious_tld else 0.0,
            "dgaScore": dga_score / 10.0,
            "homoglyphScore": 0.8 if variation_type == "typo" else 0.0,
            "reputationScore": -80 if not is_benign else 10,
        },
        "createdAt": created,
        "updatedAt": created,
        "embedding": None,  # filled later
    }


# ─────────────────────────────────────────────
# URL Generation Strategy
# Per domain we generate:
#   benign: 30 URLs  (diverse paths)
#   phishing_typo: 20 URLs
#   phishing_fake_alert: 20 URLs
#   malware: 15 URLs
#   c2: 10 URLs
#   suspicious: 5 URLs
#   → 100 URLs per domain × 10 domains = 1000 total
# ─────────────────────────────────────────────
URL_PLAN = [
    ("benign",           30, "benign"),
    ("typo",             20, "phishing"),
    ("fake_alert",       20, "phishing"),
    ("malware",          15, "malware"),
    ("c2",               10, "c2"),
    ("suspicious",        5, "suspicious"),
]  # 100 per domain


def generate_urls_for_domain(base_domain: str, campaign_id: str | None) -> list[dict]:
    """Generate 100 URL documents for a single base domain."""
    docs = []
    seen_urls: set[str] = set()

    def unique_url(url: str, idx: int) -> str:
        """Append a counter to guarantee uniqueness within this domain batch."""
        if url not in seen_urls:
            seen_urls.add(url)
            return url
        # Add unique suffix to path or query string
        sep = "&" if "?" in url else "?"
        unique = f"{url}{sep}_s={idx}"
        seen_urls.add(unique)
        return unique

    counter = 0
    for variation_type, count, threat_class in URL_PLAN:
        for _ in range(count):
            counter += 1
            # Choose domain and path
            if variation_type == "benign":
                domain = base_domain
                path = random.choice(BENIGN_PATHS)
                url = unique_url(f"https://{domain}{path}", counter)

            elif variation_type == "typo":
                domain = make_homoglyph(base_domain)
                path = random.choice(PHISHING_PATHS)
                url = unique_url(f"https://{domain}{path}", counter)

            elif variation_type == "fake_alert":
                domain = make_fake_alert_domain(base_domain)
                path = random.choice(PHISHING_PATHS)
                param = random.choice([
                    f"?next=https://{base_domain}",
                    f"?token={random.randint(100000, 999999)}",
                    f"?ref={base_domain.split('.')[0]}",
                    f"?sid={counter}",
                ])
                url = unique_url(f"https://{domain}{path}{param}", counter)

            elif variation_type == "malware":
                domain = make_malware_domain(base_domain)
                path = random.choice(MALWARE_PATHS)
                url = unique_url(f"https://{domain}{path}", counter)

            elif variation_type == "c2":
                domain = make_c2_domain(base_domain)
                path = random.choice(C2_PATHS)
                url = unique_url(f"https://{domain}{path}", counter)

            elif variation_type == "suspicious":
                domain = make_suspicious_domain(base_domain)
                path = random.choice(SUSPICIOUS_PATHS)
                url = unique_url(f"https://{domain}{path}", counter)

            else:
                continue

            doc = build_url_record(url, domain, base_domain, threat_class, variation_type, campaign_id)
            docs.append(doc)

    return docs


# ─────────────────────────────────────────────
# Embedding
# ─────────────────────────────────────────────
async def get_batch_embeddings(texts: list[str]) -> list[list[float]]:
    """Call Voyage AI in batches."""
    all_embeddings: list[list[float]] = []
    async with httpx.AsyncClient(timeout=120.0) as client:
        for i in range(0, len(texts), EMBED_BATCH_SIZE):
            batch = texts[i:i + EMBED_BATCH_SIZE]
            logger.info(f"  Embedding batch {i // EMBED_BATCH_SIZE + 1}/{math.ceil(len(texts) / EMBED_BATCH_SIZE)} ({len(batch)} texts)")
            resp = await client.post(
                VOYAGE_URL,
                headers={"Authorization": f"Bearer {VOYAGE_API_KEY}", "Content-Type": "application/json"},
                json={"input": batch, "model": VOYAGE_MODEL},
            )
            resp.raise_for_status()
            data = resp.json()
            all_embeddings.extend(item["embedding"] for item in data["data"])
    return all_embeddings


# ─────────────────────────────────────────────
# Atlas Search index definition
# ─────────────────────────────────────────────
ATLAS_SEARCH_INDEX = {
    "name": "url_search_index",
    "type": "search",
    "definition": {
        "mappings": {
            "dynamic": False,
            "fields": {
                "url": {"type": "string", "analyzer": "lucene.standard"},
                "domain": {"type": "string", "analyzer": "lucene.standard"},
                "baseDomain": {"type": "string", "analyzer": "lucene.standard"},
                "summaryText": {"type": "string", "analyzer": "lucene.standard"},
                "threatClassification": {"type": "string", "analyzer": "lucene.keyword"},
                "status": {"type": "string", "analyzer": "lucene.keyword"},
                "campaignId": {"type": "string", "analyzer": "lucene.keyword"},
                "variationType": {"type": "string", "analyzer": "lucene.keyword"},
                "riskScore": {"type": "number"},
                "createdAt": {"type": "date"},
            }
        }
    }
}

VECTOR_SEARCH_INDEX = {
    "name": "url_vector_index",
    "type": "vectorSearch",
    "definition": {
        "fields": [
            {
                "type": "vector",
                "path": "embedding",
                "numDimensions": 1024,
                "similarity": "cosine",
            },
            {"type": "filter", "path": "threatClassification"},
            {"type": "filter", "path": "status"},
            {"type": "filter", "path": "campaignId"},
        ]
    }
}


async def ensure_indexes(db):
    """Create regular MongoDB indexes on urls and campaigns collections."""
    urls = db["urls"]
    campaigns = db["campaigns"]

    logger.info("Creating MongoDB indexes on urls...")
    await urls.create_index("domain")
    await urls.create_index("baseDomain")
    await urls.create_index("canonicalDomain")
    await urls.create_index("campaignId")
    await urls.create_index("threatClassification")
    await urls.create_index("status")
    await urls.create_index([("createdAt", -1)])
    await urls.create_index([("riskScore", -1)])
    await urls.create_index("url")
    logger.info("  MongoDB URL indexes created")

    logger.info("Creating MongoDB indexes on campaigns...")
    await campaigns.create_index("campaignId", unique=True)
    await campaigns.create_index("status")
    await campaigns.create_index("attackCategory")
    await campaigns.create_index([("lastSeen", -1)])
    logger.info("  MongoDB campaign indexes created")


async def create_atlas_indexes(db):
    """Attempt to create Atlas Search + Vector Search indexes via the createSearchIndexes command."""
    try:
        result = await db.command("createSearchIndexes", "urls", indexes=[ATLAS_SEARCH_INDEX])
        logger.info(f"  Atlas Search index created: {result}")
    except Exception as e:
        if "already exists" in str(e).lower() or "IndexAlreadyExists" in str(e):
            logger.info("  Atlas Search index already exists, skipping")
        else:
            logger.warning(f"  Atlas Search index failed (expected if using local MongoDB): {e}")

    try:
        result = await db.command("createSearchIndexes", "urls", indexes=[VECTOR_SEARCH_INDEX])
        logger.info(f"  Vector Search index created: {result}")
    except Exception as e:
        if "already exists" in str(e).lower() or "IndexAlreadyExists" in str(e):
            logger.info("  Vector Search index already exists, skipping")
        else:
            logger.warning(f"  Vector Search index failed (expected if using local MongoDB): {e}")


# ─────────────────────────────────────────────
# Campaign Documents
# ─────────────────────────────────────────────
def build_campaign_doc(
    campaign: dict,
    url_docs: list[dict],
    campaign_oid_map: dict[str, str],
) -> dict:
    """Build a campaign document referencing all its threat URLs."""
    c_id = campaign["campaignId"]
    threat_urls = [d["url"] for d in url_docs if d.get("campaignId") == c_id and d["threatClassification"] != "benign"]
    threat_domains = list({d["baseDomain"] for d in url_docs if d.get("campaignId") == c_id})
    risk_scores = [d["riskScore"] for d in url_docs if d.get("campaignId") == c_id and d["threatClassification"] != "benign"]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    first_seen = min((d["createdAt"] for d in url_docs if d.get("campaignId") == c_id), default=datetime.utcnow())
    last_seen = max((d.get("lastSeenAt", d["createdAt"]) for d in url_docs if d.get("campaignId") == c_id), default=datetime.utcnow())

    return {
        "campaignId": c_id,
        "name": campaign["name"],
        "attackCategory": campaign["attackCategory"],
        "severity": campaign["severity"],
        "threatActor": campaign["threatActor"],
        "target": campaign["target"],
        "status": "active",
        "urls": threat_urls,
        "domains": threat_domains,
        "urlCount": len(threat_urls),
        "domainCount": len(threat_domains),
        "avgRiskScore": avg_risk,
        "firstSeen": first_seen,
        "lastSeen": last_seen,
        "createdAt": first_seen,
        "updatedAt": last_seen,
    }


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
async def reset_and_seed(total: int = 1000, skip_embeddings: bool = False):
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    print("\n" + "=" * 80)
    print("SHIELDNET AI — FULL DATABASE RESET + FOCUSED DEMO SEED")
    print("=" * 80)

    # ── Step 1: Drop all collections ────────────────────────────────
    print("\n[1/6] Dropping all collections...")
    for col in ["urls", "campaigns", "threat_logs"]:
        await db.drop_collection(col)
        print(f"  ✓ Dropped '{col}'")

    # ── Step 2: Generate URL documents ──────────────────────────────
    print(f"\n[2/6] Generating {total} URLs across {len(ALL_DOMAINS)} domains...")
    all_docs: list[dict] = []
    per_domain = total // len(ALL_DOMAINS)  # 100 per domain

    for base_domain in ALL_DOMAINS:
        campaign_id = DOMAIN_TO_CAMPAIGN[base_domain]
        docs = generate_urls_for_domain(base_domain, campaign_id)
        all_docs.extend(docs[:per_domain])
        print(f"  ✓ {base_domain:30} {len(docs[:per_domain]):4} URLs | campaign: {campaign_id or 'standalone'}")

    # Fill remainder to hit total exactly
    remainder = total - len(all_docs)
    if remainder > 0:
        extra_domain = ALL_DOMAINS[0]
        extra_campaign = DOMAIN_TO_CAMPAIGN[extra_domain]
        extra_docs = generate_urls_for_domain(extra_domain, extra_campaign)
        all_docs.extend(extra_docs[:remainder])

    # Deduplicate by url across all domains
    seen: set[str] = set()
    deduped: list[dict] = []
    for doc in all_docs:
        if doc["url"] not in seen:
            seen.add(doc["url"])
            deduped.append(doc)
    all_docs = deduped
    print(f"\n  Total generated (after dedup): {len(all_docs)}")

    # ── Step 3: Generate embeddings ─────────────────────────────────
    if not skip_embeddings and VOYAGE_API_KEY:
        print(f"\n[3/6] Generating Voyage AI embeddings for {len(all_docs)} URLs...")
        texts = [d["summaryText"] for d in all_docs]
        try:
            embeddings = await get_batch_embeddings(texts)
            for doc, emb in zip(all_docs, embeddings):
                doc["embedding"] = emb
            print(f"  ✓ Embeddings generated (dim={len(embeddings[0])})")
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            logger.warning("Proceeding without embeddings. Vector search will not work until embeddings are backfilled.")
    else:
        reason = "API key missing" if not VOYAGE_API_KEY else "--skip-embeddings flag set"
        print(f"\n[3/6] Skipping embeddings ({reason})")
        # Zero-fill embeddings so the schema is consistent
        for doc in all_docs:
            doc["embedding"] = [0.0] * 1024

    # ── Step 4: Insert URL documents ────────────────────────────────
    print(f"\n[4/6] Inserting {len(all_docs)} URL records...")
    urls_col = db["urls"]
    result = await urls_col.insert_many(all_docs, ordered=False)
    print(f"  ✓ Inserted {len(result.inserted_ids)} URL records")

    # ── Step 5: Build and insert campaign documents ──────────────────
    print("\n[5/6] Building campaign documents...")
    campaigns_col = db["campaigns"]
    campaign_docs = []
    for camp in CAMPAIGNS:
        doc = build_campaign_doc(camp, all_docs, {})
        campaign_docs.append(doc)
        print(f"  ✓ Campaign: {camp['name']}")
        print(f"    URLs: {doc['urlCount']}  |  Domains: {doc['domainCount']}  |  Avg Risk: {doc['avgRiskScore']}")

    await campaigns_col.insert_many(campaign_docs)
    print(f"  ✓ Inserted {len(campaign_docs)} campaigns")

    # ── Step 6: Create indexes ───────────────────────────────────────
    print("\n[6/6] Creating indexes...")
    await ensure_indexes(db)
    await create_atlas_indexes(db)
    print("  ✓ Indexes created")

    # ── Summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("SEED COMPLETE — SUMMARY")
    print("=" * 80)

    total_urls = await urls_col.count_documents({})
    total_campaigns = await campaigns_col.count_documents({})

    print(f"\nCollections:")
    print(f"  urls       : {total_urls}")
    print(f"  campaigns  : {total_campaigns}")

    # Threat class breakdown
    pipeline = [{"$group": {"_id": "$threatClassification", "count": {"$sum": 1}}}]
    breakdown = {d["_id"]: d["count"] async for d in urls_col.aggregate(pipeline)}
    print(f"\nThreat Distribution:")
    for cls in ["benign", "phishing", "malware", "c2", "suspicious"]:
        bar = "█" * (breakdown.get(cls, 0) // 20)
        print(f"  {cls:12} : {breakdown.get(cls, 0):4}  {bar}")

    # Per-domain stats
    print(f"\nURLs per Domain:")
    pipeline2 = [{"$group": {"_id": "$baseDomain", "count": {"$sum": 1}}}, {"$sort": {"_id": 1}}]
    async for d in urls_col.aggregate(pipeline2):
        camp = DOMAIN_TO_CAMPAIGN.get(d["_id"], "standalone")
        print(f"  {d['_id']:30} {d['count']:4}  [{camp or 'standalone'}]")

    has_emb = await urls_col.count_documents({"embedding": {"$not": {"$elemMatch": {"$ne": 0.0}}, "$exists": True}})
    with_real_emb = total_urls - has_emb
    print(f"\nEmbeddings: {with_real_emb} real, {has_emb} zero-filled")
    if has_emb > 0 and not skip_embeddings:
        print("  → Run backfill_detection to regenerate embeddings if needed")

    print(f"\nAtlas Search Index : 'url_search_index'  (on urls collection)")
    print(f"Vector Search Index: 'url_vector_index'  (on urls.embedding, dim=1024)")
    print(f"\n{'=' * 80}")
    print("DEMO DATABASE READY")
    print("=" * 80)
    print(f"\n  10 base domains × 100 URLs = {total_urls} total records")
    print(f"  3 coordinated campaigns tracked in campaigns collection")
    print(f"  5 threat types: benign, phishing, malware, c2, suspicious")
    print(f"  Embeddings: {'real (Voyage AI)' if with_real_emb > 0 else 'zero-filled (run backfill)'}")
    print()

    client.close()


def main():
    parser = argparse.ArgumentParser(description="Reset DB and seed focused demo dataset")
    parser.add_argument("--total", type=int, default=1000, help="Total URLs to seed (default: 1000)")
    parser.add_argument("--skip-embeddings", action="store_true", help="Skip Voyage AI embedding calls")
    args = parser.parse_args()
    asyncio.run(reset_and_seed(total=args.total, skip_embeddings=args.skip_embeddings))


if __name__ == "__main__":
    main()
