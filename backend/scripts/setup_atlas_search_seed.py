"""Setup Atlas Search index mappings and targeted lexical seed docs.

Usage:
    poetry run python -m scripts.setup_atlas_search_seed
"""

import asyncio
import os
from datetime import datetime, timedelta

from motor.motor_asyncio import AsyncIOMotorClient

from utils.url_feature_extractor import build_threat_intel_text

NEW_INDEX_DEF = {
    "mappings": {
        "dynamic": False,
        "fields": {
            "url": {"type": "string"},
            "domain": {"type": "string"},
            "summaryText": {"type": "string"},
            "docType": [{"type": "string"}, {"type": "stringFacet"}],
            "source": {"type": "string"},
            "feedName": {"type": "string"},
            "threatClassification": [{"type": "string"}, {"type": "stringFacet"}],
            "attackCategory": [{"type": "string"}, {"type": "stringFacet"}],
            "payloadSignature": {"type": "string"},
            "targetDomain": {"type": "string"},
            "severity": {"type": "stringFacet"},
            "status": {"type": "stringFacet"},
            "dnsStatus": {"type": "stringFacet"},
            "riskScore": {"type": "number"},
            "payloadTypes": {"type": "string"},
            "scanCount": {"type": "number"},
        },
    }
}

SAMPLES = [
    {
        "url": "http://login-secure-verify.xyz/account?action=confirm",
        "description": "Credential harvesting landing page imitating secure account verification workflow.",
        "attackCategory": "credential_harvest",
        "threatClassification": "phishing",
        "targetDomain": "gov.in",
        "payloadSignature": "credential_harvest+open_redirect",
    },
    {
        "url": "http://secure-login-update.xyz/signin?user=admin",
        "description": "Phishing sign-in page mimicking government employee authentication portal.",
        "attackCategory": "credential_harvest",
        "threatClassification": "phishing",
        "targetDomain": "nic.in",
        "payloadSignature": "credential_harvest",
    },
    {
        "url": "http://urgent-account-verify.xyz/secure-check?uid=12345",
        "description": "Urgency-themed account verification lure to capture credentials and OTP.",
        "attackCategory": "credential_harvest",
        "threatClassification": "phishing",
        "targetDomain": "india.gov.in",
        "payloadSignature": "credential_harvest+social_engineering",
    },
]


async def main() -> None:
    client = AsyncIOMotorClient(os.getenv("MONGODB_URI"))
    db = client[os.getenv("DB_NAME", "shieldnet-ai")]

    try:
        await db.command(
            {
                "updateSearchIndex": "urls",
                "name": "url_search_index",
                "definition": NEW_INDEX_DEF,
            }
        )
        print("updated_search_index=url_search_index")
    except Exception as exc:
        print(f"updateSearchIndex_error={exc}")

    now = datetime.utcnow()
    upserts = 0

    for sample in SAMPLES:
        domain = sample["url"].split("/")[2]
        entry = {
            "url": sample["url"],
            "domain": domain,
            "docType": "threat_intel",
            "source": "threat_feed:demo_campaign_seed",
            "feedName": "DemoCampaignFeed",
            "submissionDate": now - timedelta(days=2),
            "dnsStatus": "active",
            "hostingFlags": {
                "isSharedHosting": True,
                "isCloudHosted": True,
                "hostingProvider": "cloudflare",
                "geoLocation": "NL",
                "sslValid": False,
                "domainAgeDays": 12,
            },
            "urlStructure": {
                "pathDepth": 1,
                "hasIpAddress": False,
                "hasSuspiciousTld": True,
                "entropyScore": 4.8,
                "containsEncodedChars": False,
                "subdomainCount": 1,
            },
            "threatClassification": sample["threatClassification"],
            "attackCategory": sample["attackCategory"],
            "targetDomain": sample["targetDomain"],
            "payloadSignature": sample["payloadSignature"],
            "payloadTypes": ["credential_harvest", "open_redirect"],
            "severity": "high",
            "confidence": 0.96,
            "lastVerifiedAt": now,
            "iocType": "url",
            "ttl": 120,
            "description": sample["description"],
            "riskScore": 94.0,
            "status": "blocked",
            "reviewedBy": "system_ai",
            "scanCount": 0,
            "firstSeenAt": now - timedelta(days=2),
            "lastSeenAt": now,
            "createdAt": now,
            "updatedAt": now,
        }
        entry["summaryText"] = build_threat_intel_text(entry)

        result = await db["urls"].update_one(
            {"url": entry["url"]},
            {"$set": entry, "$setOnInsert": {"embedding": None}},
            upsert=True,
        )
        if result.upserted_id is not None or result.modified_count > 0:
            upserts += 1

    seeded_count = await db["urls"].count_documents({"source": "threat_feed:demo_campaign_seed"})
    print(f"sample_docs_upserted={upserts}")
    print(f"demo_campaign_seed_docs={seeded_count}")

    try:
        res = await db.command({"listSearchIndexes": "urls", "name": "url_search_index"})
        batch = res.get("cursor", {}).get("firstBatch", [])
        print(f"url_search_index_exists={bool(batch)}")
    except Exception as exc:
        print(f"listSearchIndexes_error={exc}")

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
