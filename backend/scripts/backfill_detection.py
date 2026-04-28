"""Backfill detection fields for old URL records.

Re-runs the full detection pipeline (DGA, homoglyph, brand impersonation,
structural, TLD risk, semantic features) on every URL record that is missing
these fields, regenerates the summary text, and updates the embedding.

Usage:
    docker-compose exec backend poetry run python -m scripts.backfill_detection
"""

import asyncio
import logging
import os
import sys
import time

from motor.motor_asyncio import AsyncIOMotorClient

# Ensure the backend package root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.url_feature_extractor import (
    extract_features,
    enrich_features,
    build_summary_text,
    calculate_risk_score,
    classify_threat,
)
from services.embedding_service import get_batch_embeddings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://localhost:27017",
)
DB_NAME = os.getenv("DATABASE_NAME", "shieldnet-ai")

# Batch size for embedding API calls (Voyage AI limit = 128)
EMBED_BATCH = 64


async def backfill():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    urls_col = db["urls"]

    # Find records missing the new detection fields
    query = {
        "$or": [
            {"dgaAnalysis": {"$exists": False}},
            {"brandImpersonation": {"$exists": False}},
            {"dgaAnalysis": None},
            {"brandImpersonation": None},
        ]
    }
    total = await urls_col.count_documents(query)
    logger.info("Found %d records to backfill", total)

    if total == 0:
        logger.info("Nothing to do — all records are up to date.")
        return

    cursor = urls_col.find(query, {"_id": 1, "url": 1, "embedding": 1})
    records = await cursor.to_list(length=total)

    # Phase 1: Re-run detection pipeline (local, no API calls)
    logger.info("Phase 1: Running detection pipeline on %d records...", len(records))
    updates: list[dict] = []
    summary_texts: list[str] = []

    for rec in records:
        url = rec["url"]
        try:
            features = extract_features(url)
            features = enrich_features(url, features)
            summary_text = build_summary_text(url, features)
            risk, _breakdown = calculate_risk_score(features, url=url)
            classification = classify_threat(risk)

            updates.append({
                "_id": rec["_id"],
                "url": url,
                "dgaAnalysis": features.get("dgaAnalysis"),
                "homoglyphAnalysis": features.get("homoglyphAnalysis"),
                "structuralAnalysis": features.get("structuralAnalysis"),
                "brandImpersonation": features.get("brandImpersonation"),
                "semanticFeatures": features.get("semanticFeatures"),
                "tldRisk": features.get("tldRisk"),
                "summaryText": summary_text,
                "riskScore": risk,
                "threatClassification": classification,
                "status": "blocked" if risk >= 75 else ("under_review" if risk >= 50 else "allowed"),
            })
            summary_texts.append(summary_text)
        except Exception as e:
            logger.warning("Failed to process %s: %s", url, e)
            updates.append(None)
            summary_texts.append(None)

    valid = [(u, t) for u, t in zip(updates, summary_texts) if u is not None and t is not None]
    logger.info("Phase 1 complete: %d/%d records processed successfully", len(valid), len(records))

    # Phase 2: Regenerate embeddings in batches
    logger.info("Phase 2: Generating embeddings in batches of %d...", EMBED_BATCH)
    texts_only = [t for _, t in valid]
    all_embeddings: list[list[float]] = []

    for i in range(0, len(texts_only), EMBED_BATCH):
        batch = texts_only[i:i + EMBED_BATCH]
        batch_num = i // EMBED_BATCH + 1
        total_batches = (len(texts_only) + EMBED_BATCH - 1) // EMBED_BATCH
        logger.info("  Embedding batch %d/%d (%d texts)...", batch_num, total_batches, len(batch))
        try:
            embeddings = await get_batch_embeddings(batch)
            all_embeddings.extend(embeddings)
        except Exception as e:
            logger.error("  Embedding batch %d failed: %s — skipping", batch_num, e)
            all_embeddings.extend([None] * len(batch))
        # Rate limit: small pause between batches
        if i + EMBED_BATCH < len(texts_only):
            await asyncio.sleep(1)

    # Phase 3: Write updates to MongoDB
    logger.info("Phase 3: Writing updates to MongoDB...")
    success = 0
    failed = 0

    for idx, (update, _) in enumerate(valid):
        embedding = all_embeddings[idx] if idx < len(all_embeddings) else None
        set_doc = {
            "dgaAnalysis": update["dgaAnalysis"],
            "homoglyphAnalysis": update["homoglyphAnalysis"],
            "structuralAnalysis": update["structuralAnalysis"],
            "brandImpersonation": update["brandImpersonation"],
            "semanticFeatures": update["semanticFeatures"],
            "tldRisk": update["tldRisk"],
            "summaryText": update["summaryText"],
            "riskScore": update["riskScore"],
            "threatClassification": update["threatClassification"],
            "status": update["status"],
        }
        if embedding:
            set_doc["embedding"] = embedding

        try:
            await urls_col.update_one(
                {"_id": update["_id"]},
                {"$set": set_doc},
            )
            success += 1
        except Exception as e:
            logger.warning("Failed to update %s: %s", update["url"], e)
            failed += 1

    logger.info("Backfill complete: %d updated, %d failed out of %d total", success, failed, total)


if __name__ == "__main__":
    start = time.monotonic()
    asyncio.run(backfill())
    elapsed = time.monotonic() - start
    logger.info("Total time: %.1fs", elapsed)
