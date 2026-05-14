"""Rebuild the urls collection from the curated minimal UC dataset.

This script is intended for demo reset so /threats reflects only the minimal
high-precision UC seed data instead of historical bulk records.

Usage:
    cd backend
    poetry run python -m scripts.rebuild_urls_from_minimal_uc
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from scripts.seed_minimal_usecase_dataset import (
    BEHAVIOR_METRICS,
    INFRASTRUCTURE_INTEL,
    REGIONAL_THREATS,
    THREAT_SIGNALS,
    VISUAL_INTELLIGENCE,
)

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or "").lower()


def _status_for_risk(risk: float) -> str:
    if risk >= 75:
        return "blocked"
    if risk >= 50:
        return "under_review"
    return "allowed"


def _default_url_doc(*, uc_id: str, url: str, domain: str, scenario: str, classification: str, risk: float, source: str) -> dict:
    now = datetime.now(UTC)
    return {
        "url": url,
        "domain": domain,
        "baseDomain": domain,
        "canonicalDomain": domain,
        "ucId": uc_id,
        "scenario": scenario,
        "source": source,
        "dnsStatus": "active",
        "threatClassification": classification,
        "riskScore": round(float(risk), 1),
        "status": _status_for_risk(float(risk)),
        "statusNote": None,
        "reviewedBy": "system_ai",
        "summaryText": f"Minimal UC seed record for {scenario} ({uc_id})",
        "docType": "scan",
        "seedProfile": "minimal_fixed_uc",
        "scanCount": 1,
        "firstSeenAt": now,
        "lastSeenAt": now,
        "createdAt": now,
        "updatedAt": now,
    }


def build_minimal_url_docs() -> list[dict]:
    by_url: dict[str, dict] = {}

    def upsert(doc: dict):
        # Keep the highest-risk version if a URL appears in multiple UC records.
        existing = by_url.get(doc["url"])
        if not existing or float(doc["riskScore"]) > float(existing["riskScore"]):
            by_url[doc["url"]] = doc

    for d in THREAT_SIGNALS:
        url = d["url"]
        domain = d.get("domain") or _domain_from_url(url)
        upsert(
            _default_url_doc(
                uc_id=d["ucId"],
                url=url,
                domain=domain,
                scenario=d.get("scenario", d["ucId"]),
                classification=d.get("threatClassification", "suspicious"),
                risk=d.get("riskScore", 50),
                source="minimal_uc_seed_threat_signals",
            )
        )

    for d in REGIONAL_THREATS:
        url = d["url"]
        domain = d.get("domain") or _domain_from_url(url)
        upsert(
            _default_url_doc(
                uc_id=d["ucId"],
                url=url,
                domain=domain,
                scenario=d.get("scenario", d["ucId"]),
                classification=d.get("threatClassification", "phishing"),
                risk=d.get("riskScore", 50),
                source="minimal_uc_seed_regional_threats",
            )
        )

    for d in VISUAL_INTELLIGENCE:
        url = d["url"]
        domain = d.get("domain") or _domain_from_url(url)
        upsert(
            _default_url_doc(
                uc_id=d["ucId"],
                url=url,
                domain=domain,
                scenario=d.get("scenario", d["ucId"]),
                classification=d.get("threatClassification", "suspicious"),
                risk=d.get("riskScore", 50),
                source="minimal_uc_seed_visual_intelligence",
            )
        )

    for d in INFRASTRUCTURE_INTEL:
        domain = (d.get("domain") or "").lower()
        if not domain:
            continue
        url = f"https://{domain}/"
        upsert(
            _default_url_doc(
                uc_id=d["ucId"],
                url=url,
                domain=domain,
                scenario=d.get("scenario", d["ucId"]),
                classification=d.get("threatClassification", "suspicious"),
                risk=82 if d.get("threatClassification") in ("malware", "c2") else 68,
                source="minimal_uc_seed_infrastructure_intel",
            )
        )

    for d in BEHAVIOR_METRICS:
        url = d.get("url")
        domain = (d.get("domain") or "").lower()
        if not url and domain:
            url = f"https://{domain}/"
        if not url:
            continue
        if not domain:
            domain = _domain_from_url(url)
        upsert(
            _default_url_doc(
                uc_id=d["ucId"],
                url=url,
                domain=domain,
                scenario=d.get("scenario", d["ucId"]),
                classification=d.get("threatClassification", "suspicious"),
                risk=88 if d.get("isAnomaly") else 45,
                source="minimal_uc_seed_behavior_metrics",
            )
        )

    return list(by_url.values())


async def rebuild_urls_collection():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    urls_coll = db["urls"]

    try:
        docs = build_minimal_url_docs()

        logger.info("=" * 72)
        logger.info("Rebuilding urls collection from minimal UC dataset")
        logger.info("=" * 72)

        deleted = await urls_coll.delete_many({})
        logger.info("Cleared urls (%d deleted)", deleted.deleted_count)

        if docs:
            await urls_coll.insert_many(docs)

        total = await urls_coll.count_documents({})
        domain_count = len(await urls_coll.distinct("baseDomain"))
        logger.info("Inserted %d minimal URL docs", len(docs))
        logger.info("urls total now: %d", total)
        logger.info("unique base domains now: %d", domain_count)
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(rebuild_urls_collection())
