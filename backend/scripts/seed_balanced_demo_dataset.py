"""Seed a balanced, domain-diverse demo dataset into the urls collection.

This script is designed for demos where scanner quality should look stable and
explainable. It creates a controlled mix of:
- scan documents (docType absent -> treated as scan)
- threat intel documents (docType = threat_intel)

Usage:
    cd backend
    poetry run python -m scripts.seed_balanced_demo_dataset --total 300

Optional flags:
    --total 300               Total records to create (default: 300)
    --scan-ratio 0.4          Fraction of scan docs (default: 0.4)
    --clear-existing-demo      Remove prior demo-seeded docs before insert
    --skip-embeddings          Insert without embeddings
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
from collections import Counter
from datetime import datetime, timedelta

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")

LEGIT_BASE_DOMAINS = [
    "incometax.gov.in",
    "uidai.gov.in",
    "passportindia.gov.in",
    "digilocker.gov.in",
    "cowin.gov.in",
    "epfindia.gov.in",
    "irctc.co.in",
    "meity.gov.in",
    "ecourts.gov.in",
    "umang.gov.in",
    "cert-in.org.in",
    "pfms.nic.in",
    "data.gov.in",
    "nrega.nic.in",
    "gst.gov.in",
    "mygov.in",
    "pmkisan.gov.in",
    "vahan.parivahan.gov.in",
    "sarathi.parivahan.gov.in",
    "sso.rajasthan.gov.in",
]

MALICIOUS_WORDS_A = [
    "secure", "verify", "update", "auth", "portal", "login", "claim", "kyc", "refund", "identity",
]
MALICIOUS_WORDS_B = [
    "gov", "india", "citizen", "service", "official", "support", "document", "benefit", "tax", "aadhaar",
]
MALICIOUS_TLDS = ["xyz", "top", "icu", "buzz", "fit", "work", "cam", "rest", "monster", "tk"]

SCAN_CLASS_WEIGHTS = {
    "benign": 0.35,
    "phishing": 0.20,
    "malware": 0.20,
    "suspicious": 0.15,
    "c2": 0.10,
}

INTEL_CLASS_WEIGHTS = {
    "phishing": 0.40,
    "malware": 0.35,
    "c2": 0.25,
}

ATTACK_BY_CLASS = {
    "phishing": ["credential_harvest", "open_redirect", "brand_impersonation"],
    "malware": ["sqli", "xss", "command_injection", "malware_download", "supply_chain"],
    "c2": ["dns_tunneling", "ssrf", "beaconing"],
    "suspicious": ["obfuscated_path", "encoded_params", "young_domain"],
    "benign": ["none"],
}

PATHS_BENIGN = ["/", "/services", "/dashboard", "/citizen/login", "/status/check", "/help", "/forms"]
PATHS_MALICIOUS = [
    "/signin",
    "/auth/verify",
    "/payment/refund",
    "/api/v1/check",
    "/download/update.exe",
    "/portal/secure",
    "/confirm/account",
]


def weighted_choice(weight_map: dict[str, float]) -> str:
    labels = list(weight_map.keys())
    weights = list(weight_map.values())
    return random.choices(labels, weights=weights, k=1)[0]


def random_when(days_back: int = 60) -> datetime:
    return datetime.utcnow() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


def malicious_domain() -> str:
    left = random.choice(MALICIOUS_WORDS_A)
    right = random.choice(MALICIOUS_WORDS_B)
    num = random.randint(1, 99)
    tld = random.choice(MALICIOUS_TLDS)
    return f"{left}-{right}-{num}.{tld}"


def build_scan_doc() -> dict:
    cls = weighted_choice(SCAN_CLASS_WEIGHTS)
    attack = random.choice(ATTACK_BY_CLASS[cls])
    is_benign = cls == "benign"

    domain = random.choice(LEGIT_BASE_DOMAINS) if is_benign else malicious_domain()
    path = random.choice(PATHS_BENIGN if is_benign else PATHS_MALICIOUS)
    scheme = "https" if is_benign else random.choice(["http", "https"])

    if not is_benign and random.random() < 0.3:
        param_key = random.choice(["next", "token", "id", "redirect", "session", "data"])
        param_val = random.choice(["admin", "verify", "base64abc123", "http://evil.example", "../../etc/passwd"])
        url = f"{scheme}://{domain}{path}?{param_key}={param_val}"
    else:
        url = f"{scheme}://{domain}{path}"

    risk = {
        "benign": round(random.uniform(5, 35), 1),
        "suspicious": round(random.uniform(45, 62), 1),
        "phishing": round(random.uniform(70, 95), 1),
        "malware": round(random.uniform(75, 98), 1),
        "c2": round(random.uniform(72, 97), 1),
    }[cls]

    status = "allowed" if risk < 50 else ("under_review" if risk < 75 else "blocked")
    created = random_when()

    return {
        "url": url,
        "domain": domain,
        "canonicalDomain": domain[4:] if domain.startswith("www.") else domain,
        "submissionDate": created,
        "source": "demo_seed_scan",
        "demoSeed": True,
        "demoSeedVersion": "balanced-v1",
        "dnsStatus": "active" if is_benign else random.choice(["active", "parked", "suspended"]),
        "hostingFlags": {
            "isSharedHosting": False if is_benign else random.choice([True, False]),
            "isCloudHosted": random.choice([True, False]),
            "hostingProvider": random.choice(["aws", "azure", "gcp", "cloudflare", "unknown"]),
            "geoLocation": random.choice(["IN", "SG", "NL", "US", "DE"]),
            "sslValid": scheme == "https",
            "domainAgeDays": random.randint(365, 6000) if is_benign else random.randint(1, 180),
        },
        "urlStructure": {
            "pathDepth": len([p for p in path.split("/") if p]),
            "hasIpAddress": False,
            "hasSuspiciousTld": any(domain.endswith(f".{t}") for t in MALICIOUS_TLDS),
            "entropyScore": round(random.uniform(1.5, 3.2), 2) if is_benign else round(random.uniform(3.6, 5.4), 2),
            "containsEncodedChars": "%" in url,
            "subdomainCount": max(0, len(domain.split(".")) - 2),
        },
        "threatClassification": cls,
        "riskScore": risk,
        "status": status,
        "reviewedBy": "demo_seed",
        "summaryText": f"Demo scan record for {domain}, class {cls}, attack {attack}, risk {risk}, status {status}",
        "payloadTypes": [] if attack == "none" else [attack],
        "queryParams": {},
        "scanCount": random.randint(1, 8),
        "firstSeenAt": created - timedelta(days=random.randint(0, 20)),
        "lastSeenAt": created,
        "createdAt": created,
        "updatedAt": created,
    }


def build_intel_doc() -> dict:
    cls = weighted_choice(INTEL_CLASS_WEIGHTS)
    attack = random.choice(ATTACK_BY_CLASS[cls])

    domain = random.choice(LEGIT_BASE_DOMAINS)
    path = random.choice(PATHS_MALICIOUS)
    param_key = random.choice(["id", "redirect", "target", "host", "payload", "code"])
    param_val = random.choice([
        "<script>alert(1)</script>",
        "1' OR '1'='1'--",
        "http://fake-verify.top/login",
        "http://169.254.169.254/latest/meta-data",
        "Y3VybCBldmls",
    ])
    url = f"https://{domain}{path}?{param_key}={param_val}"

    created = random_when(120)
    severity = "critical" if cls in {"malware", "c2"} else "high"

    return {
        "url": url,
        "domain": domain,
        "docType": "threat_intel",
        "source": "threat_feed:demo_seed",
        "feedName": "DemoThreatFeed",
        "description": f"Demo threat intel entry for {cls} using {attack} pattern on {domain}",
        "attackCategory": attack,
        "targetDomain": domain,
        "payloadSignature": attack,
        "severity": severity,
        "confidence": round(random.uniform(0.78, 0.98), 2),
        "lastVerifiedAt": created,
        "iocType": "url",
        "ttl": 120,
        "submissionDate": created,
        "demoSeed": True,
        "demoSeedVersion": "balanced-v1",
        "dnsStatus": "active",
        "hostingFlags": {
            "isSharedHosting": False,
            "isCloudHosted": True,
            "hostingProvider": "unknown",
            "geoLocation": "unknown",
            "sslValid": True,
            "domainAgeDays": random.randint(300, 2500),
        },
        "urlStructure": {
            "pathDepth": len([p for p in path.split("/") if p]),
            "hasIpAddress": False,
            "hasSuspiciousTld": False,
            "entropyScore": 0.0,
            "containsEncodedChars": "%" in url,
            "subdomainCount": max(0, len(domain.split(".")) - 2),
        },
        "threatClassification": cls,
        "riskScore": round(random.uniform(82, 96), 1),
        "status": "blocked",
        "reviewedBy": "threat_feed:demo_seed",
        "summaryText": f"Demo threat intel for {domain}, class {cls}, attack {attack}, severity {severity}",
        "payloadTypes": [attack],
        "scanCount": 0,
        "firstSeenAt": created,
        "lastSeenAt": created,
        "createdAt": created,
        "updatedAt": datetime.utcnow(),
    }


async def add_embeddings_if_available(records: list[dict], skip_embeddings: bool) -> None:
    if skip_embeddings:
        return
    voyage_key = os.getenv("VOYAGE_AI_API_KEY")
    if not voyage_key or voyage_key == "your_voyage_ai_api_key":
        return

    from services.embedding_service import get_batch_embeddings

    texts = [r.get("summaryText", "") for r in records]
    embeddings = await get_batch_embeddings(texts)
    for record, emb in zip(records, embeddings):
        record["embedding"] = emb


async def seed(total: int, scan_ratio: float, clear_existing_demo: bool, skip_embeddings: bool) -> None:
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    urls = db["urls"]

    if clear_existing_demo:
        await urls.delete_many({"demoSeed": True})

    scan_total = max(1, int(total * scan_ratio))
    intel_total = max(1, total - scan_total)

    scan_docs = [build_scan_doc() for _ in range(scan_total)]
    intel_docs = [build_intel_doc() for _ in range(intel_total)]

    seen = set()
    unique_docs = []
    for doc in scan_docs + intel_docs:
        if doc["url"] in seen:
            continue
        seen.add(doc["url"])
        unique_docs.append(doc)

    await add_embeddings_if_available(unique_docs, skip_embeddings=skip_embeddings)

    if unique_docs:
        await urls.insert_many(unique_docs)

    kinds = Counter((d.get("docType") or "scan") for d in unique_docs)
    cls = Counter(d.get("threatClassification", "unknown") for d in unique_docs)
    distinct_domains = len(set(d.get("domain", "").lower() for d in unique_docs if d.get("domain")))

    print("Inserted demo records:", len(unique_docs))
    print("By docType:", dict(kinds))
    print("By class:", dict(cls))
    print("Distinct domains:", distinct_domains)

    client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed balanced demo dataset")
    parser.add_argument("--total", type=int, default=300)
    parser.add_argument("--scan-ratio", type=float, default=0.4)
    parser.add_argument("--clear-existing-demo", action="store_true")
    parser.add_argument("--skip-embeddings", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(
        seed(
            total=max(20, args.total),
            scan_ratio=min(0.9, max(0.1, args.scan_ratio)),
            clear_existing_demo=args.clear_existing_demo,
            skip_embeddings=args.skip_embeddings,
        )
    )
