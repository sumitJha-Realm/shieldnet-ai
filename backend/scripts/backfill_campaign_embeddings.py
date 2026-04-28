"""Backfill campaign-enriched embeddings for existing URL documents.

Re-embeds URLs and threat intel entries that already have a `campaignId`
but whose `summaryText` does not yet contain campaign context.  This is the
one-time migration to bring historical data in line with the campaign-aware
embedding architecture.

Run order:
  1. seed_threat_intel.py   (creates synthetic campaigns + campaign-tagged entries)
  2. backfill_campaign_embeddings.py  (enriches any existing scan docs with campaignId)

Usage:
    cd backend
    SKIP_EMBEDDINGS=true poetry run python -m scripts.backfill_campaign_embeddings   # dry-run counts
    poetry run python -m scripts.backfill_campaign_embeddings                         # full backfill
"""

import asyncio
import logging
import os
from datetime import datetime

from bson import ObjectId
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")
BATCH_SIZE = 50
SKIP_EMBEDDINGS = os.getenv("SKIP_EMBEDDINGS", "").lower() == "true"

_CAMPAIGN_CONTEXT_MARKER = "coordinated attack campaign detected"


def _build_features_from_doc(doc: dict) -> dict:
    """Extract the features dict expected by build_campaign_enriched_summary."""
    return {
        "domain": doc.get("domain", ""),
        "hostingFlags": doc.get("hostingFlags", {
            "domainAgeDays": 0, "sslValid": False,
            "isSharedHosting": False, "hostingProvider": "unknown",
            "geoLocation": "unknown",
        }),
        "urlStructure": doc.get("urlStructure", {
            "pathDepth": 0, "entropyScore": 0.0,
            "hasIpAddress": False, "hasSuspiciousTld": False,
            "containsEncodedChars": False, "subdomainCount": 0,
        }),
        "dnsStatus": doc.get("dnsStatus", "active"),
        "dgaAnalysis": doc.get("dgaAnalysis"),
        "homoglyphAnalysis": doc.get("homoglyphAnalysis"),
        "tldRisk": doc.get("tldRisk"),
        "structuralAnalysis": doc.get("structuralAnalysis"),
        "semanticFeatures": doc.get("semanticFeatures"),
        "brandImpersonation": doc.get("brandImpersonation"),
        "payloadTypes": doc.get("payloadTypes", []),
        "queryParams": doc.get("queryParams", {}),
    }


async def backfill():
    from services.embedding_service import get_batch_embeddings
    from utils.url_feature_extractor import build_campaign_enriched_summary

    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    urls_col = db["urls"]
    campaigns_col = db["campaigns"]

    # Find all URL docs with a campaignId but without campaign context in summaryText
    query = {
        "campaignId": {"$exists": True},
        "summaryText": {"$not": {"$regex": _CAMPAIGN_CONTEXT_MARKER}},
    }
    total = await urls_col.count_documents(query)
    logger.info("Found %d documents to backfill", total)

    if total == 0:
        logger.info("Nothing to backfill — all campaign-tagged docs already have enriched summaryText.")
        client.close()
        return

    # Cache campaigns to avoid repeated DB lookups
    campaign_cache: dict[str, dict] = {}

    async def get_campaign(campaign_id) -> dict | None:
        key = str(campaign_id)
        if key not in campaign_cache:
            obj_id = ObjectId(key) if not isinstance(campaign_id, ObjectId) else campaign_id
            campaign_cache[key] = await campaigns_col.find_one({"_id": obj_id}) or {}
        return campaign_cache[key] or None

    processed = 0
    skipped = 0
    cursor = urls_col.find(query)

    # Process in batches
    batch_docs: list[dict] = []
    batch_summaries: list[str] = []
    batch_campaigns: list[dict] = []

    async def flush_batch():
        nonlocal processed
        if not batch_docs:
            return

        if not SKIP_EMBEDDINGS:
            embeddings = await get_batch_embeddings(batch_summaries)
        else:
            embeddings = [None] * len(batch_docs)
            logger.info("[DRY RUN] Would embed %d docs", len(batch_docs))

        updates = []
        for doc, summary, campaign, embedding in zip(batch_docs, batch_summaries, batch_campaigns, embeddings):
            update = {
                "summaryText": summary,
                "campaignName": campaign.get("name"),
                "updatedAt": datetime.utcnow(),
            }
            if embedding:
                update["embedding"] = embedding
            updates.append((doc["_id"], update))

        for doc_id, update in updates:
            await urls_col.update_one({"_id": doc_id}, {"$set": update})
            processed += 1

        logger.info("Backfilled %d/%d documents", processed, total)
        batch_docs.clear()
        batch_summaries.clear()
        batch_campaigns.clear()

    async for doc in cursor:
        campaign = await get_campaign(doc["campaignId"])
        if not campaign:
            logger.warning("Campaign %s not found — skipping URL %s", doc.get("campaignId"), doc.get("url"))
            skipped += 1
            continue

        features = _build_features_from_doc(doc)
        enriched = build_campaign_enriched_summary(
            url=doc.get("url", ""),
            features=features,
            campaign=campaign,
            classification=doc.get("threatClassification", ""),
            risk_score=doc.get("riskScore", 0.0),
            status=doc.get("status", ""),
            scan_count=doc.get("scanCount", 1),
        )

        batch_docs.append(doc)
        batch_summaries.append(enriched)
        batch_campaigns.append(campaign)

        if len(batch_docs) >= BATCH_SIZE:
            await flush_batch()

    # Flush remaining
    await flush_batch()

    logger.info(
        "Backfill complete: %d updated, %d skipped (missing campaign)", processed, skipped
    )
    client.close()


if __name__ == "__main__":
    asyncio.run(backfill())
