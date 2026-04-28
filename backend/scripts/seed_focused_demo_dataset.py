"""
Seed a focused, campaign-clustered demo dataset for ShieldNet AI.

This script creates a VERY DEMO-FRIENDLY dataset:
- ONLY 10 base domains (easy to understand and explain)
- Each domain has 5-6 threat variations (benign, typo, fake-alert, malware, c2)
- Grouped into 3 coordinated campaigns
- Vector embeddings cluster related threats together
- Easy to show campaign detection and domain relationships

Total records: ~60 URLs across 10 domains in 3 campaigns

Usage:
    cd backend
    poetry run python -m scripts.seed_focused_demo_dataset

This CLEARS existing URLs and creates a clean, focused dataset.
"""

from __future__ import annotations

import asyncio
import os
import random
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")

# 10 base domains - mix of real Indian gov + fictional targets for phishing campaigns
BASE_DOMAINS = [
    # Campaign 1: Tax Authority Phishing (3 domains)
    {"domain": "incometax.gov.in", "target": "tax", "campaign": "campaign_001_tax_auth_2025"},
    {"domain": "gst.gov.in", "target": "gst", "campaign": "campaign_001_tax_auth_2025"},
    {"domain": "pmkisan.gov.in", "target": "subsidy", "campaign": "campaign_001_tax_auth_2025"},
    
    # Campaign 2: Banking/Payment Phishing (3 domains)
    {"domain": "sbi.co.in", "target": "banking", "campaign": "campaign_002_banking_2025"},
    {"domain": "icici.com", "target": "banking", "campaign": "campaign_002_banking_2025"},
    {"domain": "hdfc.com", "target": "banking", "campaign": "campaign_002_banking_2025"},
    
    # Campaign 3: Government ID Phishing (3 domains)
    {"domain": "aadhaar.gov.in", "target": "identity", "campaign": "campaign_003_identity_2025"},
    {"domain": "passport.gov.in", "target": "identity", "campaign": "campaign_003_identity_2025"},
    
    # Bonus: Standalone malware/C2 (2 domains - no campaign)
    {"domain": "example-legit.com", "target": "legit", "campaign": None},
    {"domain": "generic-malware.ru", "target": "malware", "campaign": None},
]

# For each base domain, create these variations:
URL_VARIATIONS = {
    "benign": {
        "description": "Clean, legitimate URL",
        "threat_class": "benign",
        "risk": (5, 25),
        "status": "allowed",
        "path": "/",
        "url_modifier": lambda domain: f"https://{domain}/",
    },
    "typo": {
        "description": "Typosquatted homoglyph - credential phishing",
        "threat_class": "phishing",
        "risk": (70, 88),
        "status": "blocked",
        "path": "/login",
        "url_modifier": lambda domain: typosquat_domain(domain),
    },
    "fake_alert": {
        "description": "Fake security/verification alert - social engineering",
        "threat_class": "phishing",
        "risk": (72, 90),
        "status": "blocked",
        "path": "/verify",
        "url_modifier": lambda domain: f"https://secure-verify-{domain.split('.')[0]}-confirm.xyz/verify",
    },
    "malware": {
        "description": "Malware distribution - executable download",
        "threat_class": "malware",
        "risk": (85, 98),
        "status": "blocked",
        "path": "/download/update.exe",
        "url_modifier": lambda domain: f"https://malware-{domain.replace('.', '-')}-host.tk/download/update.exe",
    },
    "c2": {
        "description": "Command & Control server - bot communication",
        "threat_class": "c2",
        "risk": (88, 99),
        "status": "blocked",
        "path": "/api/checkin",
        "url_modifier": lambda domain: f"https://c2-{domain.replace('.', '-')}-panel.ru/api/checkin",
    },
}


def typosquat_domain(domain: str) -> str:
    """Create homoglyph version of domain (character substitution)."""
    variations = {
        "i": ["1", "l"],
        "a": ["4"],
        "e": ["3"],
        "o": ["0"],
        "s": ["5"],
    }
    
    parts = domain.split(".")
    base = parts[0]
    tld = ".".join(parts[1:])
    
    # Find replaceable characters
    replaceable = [(i, c) for i, c in enumerate(base) if c in variations]
    
    # Replace 1-2 random characters
    if replaceable:
        to_replace = random.sample(replaceable, min(2, len(replaceable)))
        chars = list(base)
        for idx, char in to_replace:
            chars[idx] = random.choice(variations[char])
        return f"https://{''.join(chars)}.{tld}/login"
    
    return f"https://{base}.{tld}/login"


def random_when(days_back: int = 60) -> datetime:
    """Random timestamp within last N days."""
    return datetime.utcnow() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


def build_embedding_text(url: str, variation_type: str, threat_class: str, campaign: Optional[str]) -> str:
    """Create embeddings-friendly text for clustering."""
    parts = [
        url,
        variation_type,
        f"threat_{threat_class}",
    ]
    
    if campaign:
        parts.append(f"campaign_{campaign.split('_')[1]}")  # e.g., campaign_tax_auth
    
    # Add semantic context for clustering
    if threat_class == "phishing":
        parts.extend(["credential_theft", "user_deception", "identity_impersonation"])
    elif threat_class == "malware":
        parts.extend(["executable_distribution", "system_compromise", "malware_download"])
    elif threat_class == "c2":
        parts.extend(["bot_communication", "command_control", "attacker_infrastructure"])
    
    return " ".join(parts)


async def build_url_document(
    base_domain: dict,
    variation_type: str,
    variation_config: dict,
) -> dict:
    """Build a single URL document for the database."""
    
    url_modifier = variation_config["url_modifier"]
    url = url_modifier(base_domain["domain"])
    
    # Extract domain for normalization
    domain_part = url.split("://")[1].split("/")[0].lower()
    
    doc = {
        "url": url,
        "domain": domain_part,
        "threatClassification": variation_config["threat_class"],
        "status": variation_config["status"],
        "riskScore": round(random.uniform(variation_config["risk"][0], variation_config["risk"][1]), 1),
        "reasons": [variation_config["description"]],
        
        # Demo-specific fields
        "demoFocused": True,
        "demoFocusedVersion": 1,
        "variationType": variation_type,  # benign, typo, fake_alert, malware, c2
        "baseDomain": base_domain["domain"],
        
        # Campaign clustering
        "campaign": {
            "campaignId": base_domain["campaign"],
            "campaignName": base_domain["campaign"].replace("_", " ").title() if base_domain["campaign"] else None,
        } if base_domain["campaign"] else None,
        
        # Canonical domain for alignment
        "canonicalDomain": base_domain["domain"],
        "canonicalAuthorityUrl": f"https://{base_domain['domain']}/",
        
        # Risk breakdown
        "riskBreakdown": {
            "phishingKeywords": (1.0 if variation_config["threat_class"] == "phishing" else 0.0),
            "malwareKeywords": (1.0 if variation_config["threat_class"] == "malware" else 0.0),
            "c2Keywords": (1.0 if variation_config["threat_class"] == "c2" else 0.0),
            "suspiciousTLD": (0.3 if domain_part.endswith(".xyz") or domain_part.endswith(".tk") else 0.0),
            "reputationScore": (-90 if variation_config["threat_class"] != "benign" else 5),
        },
        
        # Embedding text for vector clustering
        "embeddingText": build_embedding_text(
            url,
            variation_type,
            variation_config["threat_class"],
            base_domain["campaign"],
        ),
        
        # Timestamps
        "createdAt": random_when(),
        "updatedAt": random_when(),
        "scannedAt": random_when(days_back=30),
    }
    
    return doc


async def seed_focused_demo():
    """Main seeding function."""
    
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    urls_collection = db.urls
    
    print("=" * 80)
    print("SEEDING FOCUSED DEMO DATASET")
    print("=" * 80)
    print()
    
    try:
        # Step 1: Clear existing demo data
        print("Clearing existing demo URLs...")
        result = await urls_collection.delete_many({"demoFocused": True})
        print(f"  Deleted {result.deleted_count} existing demo records")
        print()
        
        # Step 2: Generate all documents
        print("Generating focused demo dataset...")
        documents = []
        
        for base_domain in BASE_DOMAINS:
            print(f"\n  Domain: {base_domain['domain']}")
            print(f"    Campaign: {base_domain['campaign'] or 'None (standalone)'}")
            
            # Create each variation for this domain
            for variation_type, variation_config in URL_VARIATIONS.items():
                doc = await build_url_document(base_domain, variation_type, variation_config)
                documents.append(doc)
                print(f"    ✓ {variation_type.upper():12} | {doc['threatClassification']:10} | Risk: {doc['riskScore']:5.1f}")
        
        print()
        print(f"Total documents generated: {len(documents)}")
        print()
        
        # Step 3: Insert documents
        print("Inserting into database...")
        result = await urls_collection.insert_many(documents)
        print(f"  Inserted {len(result.inserted_ids)} records")
        print()
        
        # Step 4: Verify and report
        print("=" * 80)
        print("DEMO DATASET SUMMARY")
        print("=" * 80)
        print()
        
        # Count by domain
        all_docs = await urls_collection.find({"demoFocused": True}).to_list(None)
        
        domains = {}
        campaigns = {}
        threat_classes = {}
        
        for doc in all_docs:
            domain = doc.get("baseDomain")
            campaign_obj = doc.get("campaign") or {}
            campaign = campaign_obj.get("campaignId") if isinstance(campaign_obj, dict) else None
            threat_class = doc.get("threatClassification")
            
            domains[domain] = domains.get(domain, 0) + 1
            campaigns[campaign] = campaigns.get(campaign, 0) + 1
            threat_classes[threat_class] = threat_classes.get(threat_class, 0) + 1
        
        print("Domains:")
        for domain in sorted(domains.keys()):
            print(f"  {domain:25} {domains[domain]:3} URLs")
        
        print()
        print("Campaigns:")
        for campaign in sorted([c for c in campaigns.keys() if c is not None]):
            name = campaign.replace("_", " ").title()
            print(f"  {name:40} {campaigns[campaign]:3} URLs")
        print(f"  {'Standalone (no campaign)':40} {campaigns.get(None, 0):3} URLs")
        
        print()
        print("Threat Classification:")
        for threat_class in sorted(threat_classes.keys()):
            print(f"  {threat_class:15} {threat_classes[threat_class]:3} URLs")
        
        print()
        print(f"Total URLs: {len(all_docs)}")
        print()
        
        # Step 5: Show demo URLs for testing
        print("=" * 80)
        print("URLS FOR TESTING (curl commands)")
        print("=" * 80)
        print()
        
        sample_docs = random.sample(all_docs, min(8, len(all_docs)))
        
        for doc in sample_docs:
            url = doc["url"]
            print(f"curl -X POST http://localhost:8000/api/v1/scan \\")
            print(f"  -H 'Content-Type: application/json' \\")
            print(f"  -d '{{\"url\": \"{url}\"}}' # {doc.get('threatClassification')} | {doc.get('baseDomain')}")
            print()
        
        print("=" * 80)
        print("DEMO DATASET READY!")
        print("=" * 80)
        print()
        print("Key Features:")
        print("  ✓ Only 10 base domains (easy to explain)")
        print("  ✓ 5-6 variations per domain (benign, typo, fake-alert, malware, c2)")
        print("  ✓ 3 coordinated campaigns (shows campaign detection)")
        print("  ✓ ~60 total URLs (focused and manageable)")
        print("  ✓ Embedding-based clustering (similar threats group together)")
        print("  ✓ Tagged with demoFocused:True (easy to identify)")
        print()
        
    finally:
        client.close()


def main():
    """Entry point."""
    asyncio.run(seed_focused_demo())


if __name__ == "__main__":
    main()
