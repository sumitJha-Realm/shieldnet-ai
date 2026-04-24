"""Seed MongoDB with sample threat data + embeddings.

Usage:
    cd backend
    poetry run python -m scripts.seed_data
"""

import asyncio
import os
import random
import logging
from datetime import datetime, timedelta

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")

# --- Realistic sample data pools ---

MALICIOUS_DOMAINS = [
    "secure-login-gov.xyz", "nic-portal-update.tk", "gov-verify.ml",
    "india-tax-refund.club", "ministry-auth.top", "aadhaar-kyc-verify.buzz",
    "epfo-claim-status.icu", "income-tax-efiling.work", "pmo-office-urgent.cam",
    "digilocker-validate.monster", "cowin-certificate.rest", "irctc-refund.fit",
    "passport-seva-online.xyz", "nic-email-verify.tk", "gst-portal-login.ml",
    "pension-claim-gov.ga", "nrega-payment.cf", "scholarship-portal.gq",
    "e-district-services.top", "digital-india-scheme.buzz",
]

BENIGN_DOMAINS = [
    "nic.in", "india.gov.in", "incometax.gov.in", "epfindia.gov.in",
    "digilocker.gov.in", "cowin.gov.in", "irctc.co.in", "passportindia.gov.in",
    "gst.gov.in", "pensionersportal.gov.in", "nrega.nic.in",
    "scholarships.gov.in", "edistrict.up.gov.in", "digitalindia.gov.in",
    "meity.gov.in", "cert-in.org.in", "data.gov.in", "mygov.in",
]

PATHS = [
    "/login", "/verify", "/auth/callback", "/reset-password", "/download",
    "/update-kyc", "/claim/status", "/refund/process", "/certificate/download",
    "/account/verify", "/otp/validate", "/payment/confirm", "/document/upload",
    "/admin/panel", "/api/token", "", "/portal", "/services", "/dashboard",
]

THREAT_TYPES = ["phishing", "malware", "c2", "benign", "suspicious"]
DNS_STATUSES = ["active", "inactive", "suspended", "parked"]
STATUSES = ["blocked", "allowed", "under_review"]
SOURCES = ["gov_employee_report", "automated_crawler", "threat_feed"]
DEVICES = ["desktop", "mobile"]
REGIONS = [
    "Delhi, IN", "Mumbai, IN", "Bangalore, IN", "Chennai, IN", "Kolkata, IN",
    "Hyderabad, IN", "Pune, IN", "Ahmedabad, IN", "Jaipur, IN", "Lucknow, IN",
]
DEPARTMENTS = [
    "Ministry of Finance", "Ministry of Defence", "Ministry of Home Affairs",
    "Ministry of External Affairs", "Ministry of Health", "Ministry of Education",
    "Ministry of IT & Telecom", "UIDAI", "NIC", "CERT-IN",
    "Ministry of Railways", "Ministry of Commerce", "PMO", "NITI Aayog",
]
HOSTING_PROVIDERS = [
    "aws", "azure", "gcp", "digitalocean", "linode", "vultr",
    "cloudflare", "unknown-host-provider", "ovh", "hetzner",
]
GEO_LOCATIONS = ["US", "IN", "CN", "RU", "DE", "NL", "SG", "BR", "UA", "RO"]

FEED_NAMES = ["PhishTank", "OpenPhish", "NIC_Internal", "CERT-IN_Feed", "AlienVault_OTX"]


def random_date(start_days_ago: int = 90, end_days_ago: int = 0) -> datetime:
    delta = random.randint(end_days_ago, start_days_ago)
    return datetime.utcnow() - timedelta(days=delta, hours=random.randint(0, 23), minutes=random.randint(0, 59))


def build_summary(domain: str, hf: dict, us: dict, dns: str, threat: str) -> str:
    parts = [
        f"URL analysis for {domain}",
        f"threat classification {threat}",
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
    return ", ".join(parts)


def generate_url_record(is_malicious: bool) -> dict:
    if is_malicious:
        domain = random.choice(MALICIOUS_DOMAINS)
        sub = random.choice(["", "www.", "secure.", "portal.", "login.", "verify."])
        path = random.choice(PATHS)
        scheme = random.choice(["http", "https"])
        url = f"{scheme}://{sub}{domain}{path}"
        threat = random.choice(["phishing", "malware", "c2", "suspicious"])
        dns = random.choice(["active", "suspended", "parked"])
        ssl = random.random() > 0.7
        age = random.randint(1, 90)
        risk = round(random.uniform(55, 99), 1)
        status = "blocked" if risk >= 75 else "under_review"
    else:
        domain = random.choice(BENIGN_DOMAINS)
        path = random.choice(PATHS[:3] + ["", "/portal", "/services", "/dashboard", "/home", "/about", "/help", "/contact", "/faq"])
        url = f"https://{domain}{path}"
        threat = "benign"
        dns = "active"
        ssl = True
        age = random.randint(365, 7300)
        risk = round(random.uniform(2, 35), 1)
        status = "allowed"

    hf = {
        "isSharedHosting": random.random() > 0.5 if is_malicious else False,
        "isCloudHosted": random.random() > 0.4,
        "hostingProvider": random.choice(HOSTING_PROVIDERS),
        "geoLocation": random.choice(GEO_LOCATIONS),
        "sslValid": ssl,
        "domainAgeDays": age,
    }
    us = {
        "pathDepth": len([p for p in path.split("/") if p]),
        "hasIpAddress": random.random() > 0.9 if is_malicious else False,
        "hasSuspiciousTld": any(domain.endswith(t) for t in [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".club", ".work", ".icu", ".cam", ".monster", ".rest", ".fit"]),
        "entropyScore": round(random.uniform(3.5, 5.5) if is_malicious else random.uniform(1.5, 3.5), 2),
        "containsEncodedChars": random.random() > 0.6 if is_malicious else False,
        "subdomainCount": random.randint(0, 3),
    }
    summary = build_summary(domain, hf, us, dns, threat)
    created = random_date()

    return {
        "url": url,
        "domain": domain,
        "submissionDate": created,
        "source": random.choice(SOURCES),
        "dnsStatus": dns,
        "hostingFlags": hf,
        "urlStructure": us,
        "threatClassification": threat,
        "riskScore": risk,
        "status": status,
        "reviewedBy": random.choice(["system_ai", "analyst_sharma", "analyst_gupta", "analyst_patel"]),
        "summaryText": summary,
        "embedding": None,  # Will be filled by Voyage AI
        "createdAt": created,
        "updatedAt": created,
    }


def generate_threat_log(url_id, url_record: dict) -> dict:
    return {
        "urlId": url_id,
        "timestamp": random_date(60),
        "action": random.choice(["blocked", "allowed", "flagged"]),
        "userDepartment": random.choice(DEPARTMENTS),
        "userType": "gov_employee",
        "deviceType": random.choice(DEVICES),
        "ipRegion": random.choice(REGIONS),
        "aiConfidence": round(random.uniform(0.6, 0.99), 2),
    }


def generate_intel_feed() -> dict:
    domain = random.choice(MALICIOUS_DOMAINS)
    return {
        "feedName": random.choice(FEED_NAMES),
        "url": f"http://{domain}{random.choice(PATHS)}",
        "reportedDate": random_date(180),
        "threatType": random.choice(["phishing", "malware", "c2"]),
        "description": random.choice([
            f"Known phishing campaign targeting government login portals via {domain}",
            f"Malware distribution site hosting trojan payloads at {domain}",
            f"Command and control server communicating with infected government endpoints from {domain}",
            f"Credential harvesting page impersonating NIC services at {domain}",
            f"Suspicious domain {domain} flagged by multiple threat intelligence sources",
        ]),
        "embedding": None,
    }


async def seed():
    logger.info("Connecting to MongoDB at %s", MONGODB_URI)
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    # Drop existing collections
    for coll_name in ["urls", "threat_logs", "threat_intel_feeds"]:
        await db.drop_collection(coll_name)
        logger.info("Dropped collection: %s", coll_name)

    # Generate URL records (deduplicate by URL to avoid same URL with different statuses)
    url_records = []
    seen_urls = set()
    attempts = 0
    while len([r for r in url_records if r["threatClassification"] != "benign"]) < 150 and attempts < 500:
        rec = generate_url_record(is_malicious=True)
        if rec["url"] not in seen_urls:
            seen_urls.add(rec["url"])
            url_records.append(rec)
        attempts += 1
    attempts = 0
    while len([r for r in url_records if r["threatClassification"] == "benign"]) < 70 and attempts < 500:
        rec = generate_url_record(is_malicious=False)
        if rec["url"] not in seen_urls:
            seen_urls.add(rec["url"])
            url_records.append(rec)
        attempts += 1
    random.shuffle(url_records)
    logger.info("Generated %d unique URL records", len(url_records))

    # Generate embeddings if Voyage AI key is available
    voyage_key = os.getenv("VOYAGE_AI_API_KEY")
    if voyage_key and voyage_key != "your_voyage_ai_api_key":
        logger.info("Generating embeddings via Voyage AI...")
        import httpx

        summaries = [r["summaryText"] for r in url_records]
        batch_size = 128
        all_embeddings = []

        try:
            async with httpx.AsyncClient() as http_client:
                for i in range(0, len(summaries), batch_size):
                    batch = summaries[i : i + batch_size]
                    logger.info("  Embedding batch %d-%d of %d", i + 1, i + len(batch), len(summaries))
                    resp = await http_client.post(
                        "https://ai.mongodb.com/v1/embeddings",
                        headers={
                            "Authorization": f"Bearer {voyage_key}",
                            "Content-Type": "application/json",
                        },
                        json={"input": batch, "model": os.getenv("VOYAGE_MODEL", "voyage-4")},
                        timeout=120.0,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    all_embeddings.extend(item["embedding"] for item in data["data"])

            for rec, emb in zip(url_records, all_embeddings):
                rec["embedding"] = emb
            logger.info("Embeddings generated for %d URL records", len(all_embeddings))
        except Exception as e:
            logger.warning("Embedding generation failed (%s). Inserting WITHOUT embeddings.", e)
    else:
        logger.warning("VOYAGE_AI_API_KEY not set — inserting records WITHOUT embeddings.")

    # Insert URL records
    result = await db["urls"].insert_many(url_records)
    inserted_ids = result.inserted_ids
    logger.info("Inserted %d URL records", len(inserted_ids))

    # Generate threat logs
    threat_logs = []
    for _ in range(500):
        idx = random.randint(0, len(inserted_ids) - 1)
        log = generate_threat_log(inserted_ids[idx], url_records[idx])
        threat_logs.append(log)

    await db["threat_logs"].insert_many(threat_logs)
    logger.info("Inserted %d threat logs", len(threat_logs))

    # Generate threat intel feeds
    intel_feeds = [generate_intel_feed() for _ in range(50)]

    if voyage_key and voyage_key != "your_voyage_ai_api_key":
        logger.info("Generating embeddings for intel feeds...")
        import httpx

        descriptions = [f["description"] for f in intel_feeds]
        try:
            async with httpx.AsyncClient() as http_client:
                resp = await http_client.post(
                    "https://ai.mongodb.com/v1/embeddings",
                    headers={
                        "Authorization": f"Bearer {voyage_key}",
                        "Content-Type": "application/json",
                    },
                    json={"input": descriptions, "model": os.getenv("VOYAGE_MODEL", "voyage-4")},
                    timeout=120.0,
                )
                resp.raise_for_status()
                data = resp.json()
                for feed, emb_data in zip(intel_feeds, data["data"]):
                    feed["embedding"] = emb_data["embedding"]
        except Exception as e:
            logger.warning("Intel feed embedding failed (%s). Inserting WITHOUT embeddings.", e)

    await db["threat_intel_feeds"].insert_many(intel_feeds)
    logger.info("Inserted %d threat intel feeds", len(intel_feeds))

    # Create indexes
    await db["urls"].create_index("url")
    await db["urls"].create_index("domain")
    await db["urls"].create_index("threatClassification")
    await db["urls"].create_index("status")
    await db["urls"].create_index("createdAt")
    await db["urls"].create_index("riskScore")
    await db["threat_logs"].create_index("urlId")
    await db["threat_logs"].create_index("timestamp")
    logger.info("MongoDB indexes created")

    # Create Atlas Search indexes using PyMongo's native API
    from pymongo.operations import SearchIndexModel

    atlas_search_index = os.getenv("ATLAS_SEARCH_INDEX", "url_search_index")
    vector_search_index = os.getenv("VECTOR_SEARCH_INDEX", "url_vector_index")

    # Atlas full-text search index
    try:
        await db["urls"].create_search_index(
            SearchIndexModel(
                definition={
                    "mappings": {
                        "dynamic": False,
                        "fields": {
                            "url": {"type": "string"},
                            "domain": {"type": "string"},
                            "summaryText": {"type": "string"},
                            "threatClassification": [{"type": "string"}, {"type": "stringFacet"}],
                            "status": {"type": "stringFacet"},
                            "dnsStatus": {"type": "stringFacet"},
                            "riskScore": {"type": "number"},
                        },
                    },
                },
                name=atlas_search_index,
                type="search",
            )
        )
        logger.info("Atlas Search index created: %s", atlas_search_index)
    except Exception as e:
        if "already exists" in str(e).lower() or "IndexAlreadyExists" in str(e):
            logger.info("Atlas Search index '%s' already exists", atlas_search_index)
        else:
            logger.warning("Could not create Atlas Search index: %s", e)

    # Vector search index
    try:
        await db["urls"].create_search_index(
            SearchIndexModel(
                definition={
                    "fields": [
                        {
                            "type": "vector",
                            "path": "embedding",
                            "numDimensions": 1024,
                            "similarity": "cosine",
                        },
                        {
                            "type": "filter",
                            "path": "threatClassification",
                        },
                        {
                            "type": "filter",
                            "path": "status",
                        },
                    ],
                },
                name=vector_search_index,
                type="vectorSearch",
            )
        )
        logger.info("Vector Search index created: %s", vector_search_index)
    except Exception as e:
        if "already exists" in str(e).lower() or "IndexAlreadyExists" in str(e):
            logger.info("Vector Search index '%s' already exists", vector_search_index)
        else:
            logger.warning("Could not create Vector Search index: %s", e)

    logger.info("Seeding complete!")
    client.close()


if __name__ == "__main__":
    asyncio.run(seed())
