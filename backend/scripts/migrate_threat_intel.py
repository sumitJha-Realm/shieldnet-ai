"""Migrate threat_intel_feeds documents into the unified urls collection.

Adds docType="threat_intel" to distinguish them from scanned URLs (docType="scan").
Also backfills docType="scan" on existing urls documents.

Usage:
    docker-compose exec backend poetry run python -m scripts.migrate_threat_intel
"""

import asyncio
import os
import logging
from datetime import datetime

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")


async def migrate():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    # 1. Backfill docType="scan" on existing urls docs that don't have it
    result = await db["urls"].update_many(
        {"docType": {"$exists": False}},
        {"$set": {"docType": "scan"}},
    )
    logger.info("Backfilled docType='scan' on %d existing url documents", result.modified_count)

    # 2. Copy threat_intel_feeds into urls with docType="threat_intel"
    ti_count = await db["threat_intel_feeds"].count_documents({})
    if ti_count == 0:
        logger.info("No threat_intel_feeds documents to migrate")
        client.close()
        return

    logger.info("Found %d threat_intel_feeds documents to migrate", ti_count)

    batch_size = 200
    migrated = 0
    skipped = 0

    cursor = db["threat_intel_feeds"].find({})
    batch = []

    async for doc in cursor:
        # Map threat_intel_feeds fields → urls-compatible document
        new_doc = {
            "url": doc.get("url", ""),
            "domain": _extract_domain(doc.get("url", "")),
            "docType": "threat_intel",
            "source": f"threat_feed:{doc.get('feedName', 'unknown')}",
            "submissionDate": doc.get("reportedDate", datetime.utcnow()),
            "dnsStatus": "active",
            "hostingFlags": {
                "isSharedHosting": False,
                "isCloudHosted": True,
                "hostingProvider": "unknown",
                "geoLocation": "unknown",
                "sslValid": doc.get("url", "").startswith("https"),
                "domainAgeDays": 365,
            },
            "urlStructure": {
                "pathDepth": doc.get("url", "").count("/") - 2,
                "hasIpAddress": False,
                "hasSuspiciousTld": False,
                "entropyScore": 0.0,
                "containsEncodedChars": "%" in doc.get("url", ""),
                "subdomainCount": 0,
            },
            "threatClassification": doc.get("threatType", "malware"),
            "riskScore": 90.0,  # Threat intel entries are high-risk by definition
            "status": "blocked",
            "reviewedBy": f"threat_feed:{doc.get('feedName', 'unknown')}",
            "summaryText": doc.get("summaryText", ""),
            "embedding": doc.get("embedding"),
            # Threat intel specific metadata
            "feedName": doc.get("feedName"),
            "description": doc.get("description", ""),
            "attackCategory": doc.get("attackCategory"),
            "targetDomain": doc.get("targetDomain"),
            "payloadSignature": doc.get("payloadSignature"),
            "severity": doc.get("severity"),
            "confidence": doc.get("confidence"),
            "lastVerifiedAt": doc.get("lastVerifiedAt"),
            "iocType": doc.get("iocType", "url"),
            "ttl": doc.get("ttl"),
            "payloadTypes": [doc["attackCategory"]] if doc.get("attackCategory") else [],
            "scanCount": 0,
            "firstSeenAt": doc.get("reportedDate", datetime.utcnow()),
            "lastSeenAt": doc.get("lastVerifiedAt", datetime.utcnow()),
            "createdAt": doc.get("reportedDate", datetime.utcnow()),
            "updatedAt": datetime.utcnow(),
        }

        # Check if this URL already exists in urls (avoid duplicates)
        existing = await db["urls"].find_one({"url": new_doc["url"], "docType": "threat_intel"})
        if existing:
            skipped += 1
            continue

        batch.append(new_doc)

        if len(batch) >= batch_size:
            await db["urls"].insert_many(batch)
            migrated += len(batch)
            logger.info("Migrated %d/%d documents", migrated, ti_count)
            batch = []

    if batch:
        await db["urls"].insert_many(batch)
        migrated += len(batch)

    logger.info("Migration complete: %d migrated, %d skipped (duplicates)", migrated, skipped)
    logger.info("Total urls collection size: %d", await db["urls"].count_documents({}))

    client.close()


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


if __name__ == "__main__":
    asyncio.run(migrate())
