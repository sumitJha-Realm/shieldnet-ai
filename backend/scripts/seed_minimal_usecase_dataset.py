"""Seed a high-precision demo dataset with targeted miss-case expansion.

Goal:
- Keep URLs curated and deterministic
- Use a fixed embedding text template for consistent vector behavior
- Keep Search collections lean for deterministic demo evidence
- Add targeted cases for miss patterns and improve label balance

Collections seeded:
- threat_signals (vector)
- regional_threats (vector, multilingual)
- visual_intelligence (vector)
- infrastructure_intel (search)
- behavior_metrics (search)

Usage:
    cd backend
    poetry run python -m scripts.seed_minimal_usecase_dataset
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

# Add backend root for service imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.embedding_service import get_batch_embeddings, VoyageModel

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")


def fixed_embedding_text(
    uc_id: str,
    collection_name: str,
    scenario: str,
    url: str,
    domain: str,
    threat_class: str,
    attack_category: str,
    signals: list[str],
    evidence: str,
) -> str:
    """Fixed embedding template used for every vectorized record.

    The exact field order stays constant to reduce embedding-format variance.
    """
    return (
        f"uc:{uc_id} | collection:{collection_name} | scenario:{scenario} | "
        f"url:{url} | domain:{domain} | class:{threat_class} | category:{attack_category} | "
        f"signals:{';'.join(signals)} | evidence:{evidence}"
    )


THREAT_SIGNALS = [
    {
        "ucId": "UC01",
        "scenario": "Typosquatting",
        "url": "https://sbi-secure-login.com/verify",
        "domain": "sbi-secure-login.com",
        "attackCategory": "typosquatting",
        "threatClassification": "phishing",
        "riskScore": 92,
        "signals": ["brand_distance", "fake_login", "young_domain"],
        "evidence": "Mimics SBI netbanking login flow.",
    },
    {
        "ucId": "UC02",
        "scenario": "Phishing URL Identification",
        "url": "https://secure-hdfc-banking.in/netbanking/login",
        "domain": "secure-hdfc-banking.in",
        "attackCategory": "phishing",
        "threatClassification": "phishing",
        "riskScore": 95,
        "signals": ["credential_harvest", "otp_lure", "brand_impersonation"],
        "evidence": "Clone login page requesting sensitive fields.",
    },
    {
        "ucId": "UC03",
        "scenario": "Threat Intel Feed Match",
        "url": "https://login-microsoft365-verify.com/auth",
        "domain": "login-microsoft365-verify.com",
        "attackCategory": "credential_harvesting",
        "threatClassification": "phishing",
        "riskScore": 98,
        "signals": ["feed_match", "m365_lure", "fresh_registration"],
        "evidence": "Known credential campaign indicator.",
    },
    {
        "ucId": "UC04",
        "scenario": "Government Impersonation",
        "url": "https://aadhaar-update-portal.in/ekyc",
        "domain": "aadhaar-update-portal.in",
        "attackCategory": "government_impersonation",
        "threatClassification": "phishing",
        "riskScore": 97,
        "signals": ["gov_brand_abuse", "kyc_lure", "otp_harvest"],
        "evidence": "Impersonates Aadhaar update process.",
    },
    {
        "ucId": "UC05",
        "scenario": "Homoglyph / IDN Attack",
        "url": "https://xn--gogle-mra.com/login",
        "domain": "xn--gogle-mra.com",
        "attackCategory": "homoglyph_attack",
        "threatClassification": "phishing",
        "riskScore": 94,
        "signals": ["idn_punycode", "visual_impersonation", "brand_clone"],
        "evidence": "Punycode domain visually mimics google.com.",
    },
    {
        "ucId": "UC06",
        "scenario": "Shortener Abuse",
        "url": "https://bit.ly/3xR7kQm",
        "domain": "bit.ly",
        "attackCategory": "shortener_abuse",
        "threatClassification": "phishing",
        "riskScore": 89,
        "signals": ["known_shortener", "redirect_abuse", "messaging_distribution"],
        "evidence": "Short URL redirects to credential phishing destination.",
    },
    {
        "ucId": "UC07",
        "scenario": "Brand Impersonation",
        "url": "https://icici-bank-rewards.com/claim",
        "domain": "icici-bank-rewards.com",
        "attackCategory": "brand_impersonation",
        "threatClassification": "phishing",
        "riskScore": 91,
        "signals": ["brand_logo_clone", "reward_lure", "card_data_harvest"],
        "evidence": "Fake rewards claim page harvesting payment details.",
    },
    {
        "ucId": "UC08",
        "scenario": "Malware Distribution",
        "url": "https://free-software-download.xyz/adobe-reader-update.exe",
        "domain": "free-software-download.xyz",
        "attackCategory": "malware_distribution",
        "threatClassification": "malware",
        "riskScore": 96,
        "signals": ["exe_payload", "fake_update", "suspicious_tld"],
        "evidence": "Executable payload disguised as legitimate software update.",
    },
]


REGIONAL_THREATS = [
    {
        "ucId": "UC09",
        "scenario": "Hindi Banking Scam",
        "url": "https://sbi-kyc-update.in/verify",
        "domain": "sbi-kyc-update.in",
        "language": "hi",
        "attackCategory": "banking_scam",
        "threatClassification": "phishing",
        "riskScore": 90,
        "originalText": "प्रिय ग्राहक, आपका SBI खाता ब्लॉक हो गया है। तुरंत KYC अपडेट करें अन्यथा 24 घंटे में खाता बंद कर दिया जाएगा।",
        "signals": ["hindi_script", "kyc_urgency", "banking_lure"],
        "evidence": "Threatens account closure to force user action.",
    },
    {
        "ucId": "UC10",
        "scenario": "Tamil EPFO Scam",
        "url": "https://epfo-claim-status.in/check",
        "domain": "epfo-claim-status.in",
        "language": "ta",
        "attackCategory": "government_impersonation",
        "threatClassification": "phishing",
        "riskScore": 88,
        "originalText": "உங்கள் EPFO கணக்கில் ₹15,000 நிலுவை உள்ளது. இப்போதே பெற கீழே உள்ள இணைப்பை கிளிக் செய்யவும்.",
        "signals": ["tamil_script", "epfo_lure", "bank_details_harvest"],
        "evidence": "Government-benefit lure targeting worker accounts.",
    },
    {
        "ucId": "UC11",
        "scenario": "Bengali PM-KISAN Scam",
        "url": "https://pm-kisan-samman.in/apply",
        "domain": "pm-kisan-samman.in",
        "language": "bn",
        "attackCategory": "government_impersonation",
        "threatClassification": "phishing",
        "riskScore": 87,
        "originalText": "প্রিয় কৃষক, আপনার PM-KISAN ₹6000 জমা হয়েছে। এখনই নিন এবং আধার নম্বর দিন।",
        "signals": ["bengali_script", "subsidy_lure", "aadhaar_harvest"],
        "evidence": "Fake subsidy disbursement message.",
    },
    {
        "ucId": "UC12",
        "scenario": "Hindi PAN-Aadhaar Scam",
        "url": "https://aadhaar-link-pan.in/update",
        "domain": "aadhaar-link-pan.in",
        "language": "hi",
        "attackCategory": "government_impersonation",
        "threatClassification": "phishing",
        "riskScore": 91,
        "originalText": "आयकर विभाग: आपका PAN आधार से लिंक नहीं है। तुरंत लिंक करें अन्यथा PAN निष्क्रिय हो जाएगा।",
        "signals": ["hindi_script", "tax_authority_impersonation", "deadline_threat"],
        "evidence": "Regulatory urgency pressure tactic.",
    },
]


VISUAL_INTELLIGENCE = [
    {
        "ucId": "UC13",
        "scenario": "Visual Baseline SBI",
        "url": "https://onlinesbi.sbi",
        "domain": "onlinesbi.sbi",
        "type": "baseline",
        "attackCategory": "baseline",
        "threatClassification": "benign",
        "riskScore": 12,
        "description": "Official SBI login baseline with expected branding and security controls.",
        "signals": ["baseline_ui", "trusted_brand", "expected_layout"],
        "evidence": "Reference baseline page for visual comparison.",
    },
    {
        "ucId": "UC14",
        "scenario": "Visual Clone SBI",
        "url": "https://sbi-secure-login.com/verify",
        "domain": "sbi-secure-login.com",
        "type": "phishing_capture",
        "attackCategory": "visual_impersonation",
        "threatClassification": "phishing",
        "riskScore": 92,
        "description": "Near-identical SBI clone with missing controls and added harvest fields.",
        "signals": ["clone_layout", "missing_security_elements", "credential_prompt"],
        "evidence": "Visual mismatch against official baseline.",
    },
    {
        "ucId": "UC15",
        "scenario": "Visual Baseline HDFC",
        "url": "https://hdfcbank.com",
        "domain": "hdfcbank.com",
        "type": "baseline",
        "attackCategory": "baseline",
        "threatClassification": "benign",
        "riskScore": 10,
        "description": "Official HDFC homepage baseline.",
        "signals": ["baseline_ui", "trusted_brand", "expected_navigation"],
        "evidence": "Reference baseline page for HDFC.",
    },
    {
        "ucId": "UC16",
        "scenario": "Visual Clone HDFC",
        "url": "https://secure-hdfc-banking.in/netbanking/login",
        "domain": "secure-hdfc-banking.in",
        "type": "phishing_capture",
        "attackCategory": "visual_impersonation",
        "threatClassification": "phishing",
        "riskScore": 93,
        "description": "Impersonates HDFC layout while requesting high-risk credential fields.",
        "signals": ["brand_clone", "fake_login_form", "harvest_fields"],
        "evidence": "Visual and form-semantics mismatch with baseline.",
    },
    {
        "ucId": "UC17",
        "scenario": "Gov Portal Baseline",
        "url": "https://eprocure.gov.in",
        "domain": "eprocure.gov.in",
        "type": "baseline",
        "attackCategory": "baseline",
        "threatClassification": "benign",
        "riskScore": 14,
        "description": "Official eprocurement portal baseline with expected content.",
        "signals": ["gov_baseline", "expected_dom_structure", "no_injected_script"],
        "evidence": "Reference page for watering-hole diff.",
    },
    {
        "ucId": "UC18",
        "scenario": "Watering Hole Variant",
        "url": "https://eprocure.gov.in?variant=compromised",
        "domain": "eprocure.gov.in",
        "type": "watering_hole_diff",
        "attackCategory": "watering_hole",
        "threatClassification": "suspicious",
        "riskScore": 78,
        "description": "Compromised variant with hidden malicious script load.",
        "signals": ["hidden_iframe", "script_injection", "supply_chain_signal"],
        "evidence": "Behavior differs from government baseline despite similar look.",
    },
]


INFRASTRUCTURE_INTEL = [
    {
        "ucId": "UC19",
        "domain": "sbi-secure-login.com",
        "status": "active",
        "hostingProvider": "bulletproof-host-ru",
        "asn": "AS13335",
        "attackCategory": "phishing_infra",
        "threatClassification": "phishing",
        "scenario": "Known Phish Host",
    },
    {
        "ucId": "UC20",
        "domain": "click-track-offer.com",
        "status": "active",
        "hostingProvider": "m247",
        "asn": "AS9009",
        "attackCategory": "redirect_chain",
        "threatClassification": "suspicious",
        "scenario": "Redirect Chain Infrastructure",
    },
    {
        "ucId": "UC21",
        "domain": "secure-banking-portal.xyz",
        "status": "active",
        "hostingProvider": "unknown-vps",
        "asn": "AS48031",
        "attackCategory": "tls_anomaly",
        "threatClassification": "suspicious",
        "scenario": "TLS Anomaly",
    },
    {
        "ucId": "UC22",
        "domain": "fast-flux-botnet.top",
        "status": "fast-flux",
        "hostingProvider": "distributed-botnet",
        "asn": "AS-MULTIPLE",
        "attackCategory": "fast_flux",
        "threatClassification": "c2",
        "scenario": "Fast-Flux Botnet",
    },
    {
        "ucId": "UC23",
        "domain": "update-service-cdn.buzz",
        "status": "fast-flux",
        "hostingProvider": "residential-proxy",
        "asn": "AS-MULTIPLE",
        "attackCategory": "fast_flux_variant",
        "threatClassification": "malware",
        "scenario": "Fast-Flux Variant",
    },
    {
        "ucId": "UC24",
        "domain": "cdn-analytics-lib.com",
        "status": "active",
        "hostingProvider": "cloudflare",
        "asn": "AS13335",
        "attackCategory": "supply_chain",
        "threatClassification": "malware",
        "scenario": "Supply Chain CDN",
    },
]


BEHAVIOR_METRICS = [
    {
        "ucId": "UC25",
        "domain": "sbi-secure-login.com",
        "url": "https://sbi-secure-login.com/verify",
        "requestsPerMinute": 450.0,
        "errorRate5xx": 0.02,
        "avgTimeBetweenRequests": 15.0,
        "anomalyType": "credential_stuffing",
        "threatClassification": "phishing",
        "isAnomaly": True,
        "scenario": "Behavior Anomaly",
    }
]


# Targeted expansion (+24 URLs) for miss classes: malware, suspicious, c2, benign hard negatives.
THREAT_SIGNALS.extend(
    [
        {
            "ucId": "UC26",
            "scenario": "UPI Reward Scam",
            "url": "https://upi-cashback-reward.in/claim-now",
            "domain": "upi-cashback-reward.in",
            "attackCategory": "brand_impersonation",
            "threatClassification": "phishing",
            "riskScore": 90,
            "signals": ["upi_lure", "cashback_promise", "otp_harvest"],
            "evidence": "Fake UPI reward flow requests OTP and PIN details.",
        },
        {
            "ucId": "UC27",
            "scenario": "Courier Delivery Credential Scam",
            "url": "https://track-courier-redelivery.in/pay-fee",
            "domain": "track-courier-redelivery.in",
            "attackCategory": "credential_harvesting",
            "threatClassification": "phishing",
            "riskScore": 88,
            "signals": ["delivery_lure", "small_fee_bait", "card_harvest"],
            "evidence": "Redelivery lure used to collect card and contact data.",
        },
        {
            "ucId": "UC28",
            "scenario": "Drive-by JavaScript Dropper",
            "url": "https://player-codec-update.xyz/install",
            "domain": "player-codec-update.xyz",
            "attackCategory": "drive_by_download",
            "threatClassification": "malware",
            "riskScore": 95,
            "signals": ["drive_by_js", "auto_download", "payload_fetch"],
            "evidence": "Malicious script initiates silent binary download.",
        },
        {
            "ucId": "UC29",
            "scenario": "Fake Browser Update",
            "url": "https://chrome-security-patch.cc/update.pkg",
            "domain": "chrome-security-patch.cc",
            "attackCategory": "malware_distribution",
            "threatClassification": "malware",
            "riskScore": 96,
            "signals": ["fake_update", "installer_payload", "unsigned_binary"],
            "evidence": "Impersonates browser update channel to distribute malware.",
        },
        {
            "ucId": "UC30",
            "scenario": "Document Macro Dropper",
            "url": "https://invoice-review-download.top/invoice.docm",
            "domain": "invoice-review-download.top",
            "attackCategory": "malware_distribution",
            "threatClassification": "malware",
            "riskScore": 93,
            "signals": ["docm_payload", "macro_execution", "loader_chain"],
            "evidence": "Macro-enabled document triggers staged malware chain.",
        },
        {
            "ucId": "UC31",
            "scenario": "Cracked Software Trojan",
            "url": "https://pro-editor-crack-download.site/setup.exe",
            "domain": "pro-editor-crack-download.site",
            "attackCategory": "trojan_distribution",
            "threatClassification": "malware",
            "riskScore": 91,
            "signals": ["piracy_lure", "trojan_dropper", "c2_bootstrap"],
            "evidence": "Cracked software installer drops remote-access trojan.",
        },
        {
            "ucId": "UC32",
            "scenario": "Beacon C2 Endpoint",
            "url": "https://device-sync-control.net/ping",
            "domain": "device-sync-control.net",
            "attackCategory": "command_and_control",
            "threatClassification": "c2",
            "riskScore": 92,
            "signals": ["periodic_beacon", "low_ttl_rotation", "encrypted_post"],
            "evidence": "Regular beacon pattern to rotating control endpoint.",
        },
        {
            "ucId": "UC33",
            "scenario": "Pre-Landing Redirect Broker",
            "url": "https://auth-gateway-checker.net/route",
            "domain": "auth-gateway-checker.net",
            "attackCategory": "redirect_chain",
            "threatClassification": "suspicious",
            "riskScore": 84,
            "signals": ["multi_hop_redirect", "campaign_token", "short_lived_host"],
            "evidence": "Traffic broker domain forwards victims to final payload pages.",
        },
    ]
)

REGIONAL_THREATS.extend(
    [
        {
            "ucId": "UC34",
            "scenario": "Hindi Courier OTP Scam",
            "url": "https://india-post-redelivery.in/otp",
            "domain": "india-post-redelivery.in",
            "language": "hi",
            "attackCategory": "phishing",
            "threatClassification": "phishing",
            "riskScore": 89,
            "originalText": "डिलीवरी शुल्क ₹15 जमा करें और OTP दर्ज करें, अन्यथा पार्सल रद्द कर दिया जाएगा।",
            "signals": ["hindi_script", "delivery_lure", "otp_collection"],
            "evidence": "Delivery urgency used to harvest OTP.",
        },
        {
            "ucId": "UC35",
            "scenario": "Tamil UPI Refund Scam",
            "url": "https://upi-refund-settlement.in/verify",
            "domain": "upi-refund-settlement.in",
            "language": "ta",
            "attackCategory": "phishing",
            "threatClassification": "phishing",
            "riskScore": 90,
            "originalText": "உங்கள் UPI பணம் திருப்பி அனுப்ப தயவுசெய்து PIN மற்றும் OTP ஐ சரிபார்க்கவும்.",
            "signals": ["tamil_script", "refund_lure", "upi_pin_harvest"],
            "evidence": "UPI refund pretext to collect sensitive credentials.",
        },
        {
            "ucId": "UC36",
            "scenario": "Bengali KYC Renewal Scam",
            "url": "https://bank-kyc-renewal.co.in/confirm",
            "domain": "bank-kyc-renewal.co.in",
            "language": "bn",
            "attackCategory": "phishing",
            "threatClassification": "phishing",
            "riskScore": 88,
            "originalText": "আপনার KYC মেয়াদ শেষ হয়েছে, এখনই আপডেট না করলে অ্যাকাউন্ট বন্ধ হবে।",
            "signals": ["bengali_script", "kyc_pressure", "account_closure_threat"],
            "evidence": "Threat of account closure for KYC urgency.",
        },
        {
            "ucId": "UC37",
            "scenario": "Malayalam Subsidy Claim Scam",
            "url": "https://state-benefit-release.in/claim",
            "domain": "state-benefit-release.in",
            "language": "ml",
            "attackCategory": "phishing",
            "threatClassification": "phishing",
            "riskScore": 86,
            "originalText": "നിങ്ങളുടെ സബ്സിഡി തുക ലഭിക്കാൻ ഉടൻ ആധാർയും ബാങ്ക് വിവരങ്ങളും നൽകുക.",
            "signals": ["malayalam_script", "subsidy_lure", "aadhaar_bank_harvest"],
            "evidence": "Government subsidy lure targeting bank details.",
        },
    ]
)

VISUAL_INTELLIGENCE.extend(
    [
        {
            "ucId": "UC38",
            "scenario": "Visual Baseline Axis Bank",
            "url": "https://www.axisbank.com",
            "domain": "www.axisbank.com",
            "type": "baseline",
            "attackCategory": "baseline",
            "threatClassification": "benign",
            "riskScore": 11,
            "description": "Official Axis Bank baseline with expected trust indicators.",
            "signals": ["baseline_ui", "trusted_brand", "valid_nav"],
            "evidence": "Legitimate baseline for visual diff checks.",
        },
        {
            "ucId": "UC39",
            "scenario": "Visual Baseline LIC",
            "url": "https://licindia.in",
            "domain": "licindia.in",
            "type": "baseline",
            "attackCategory": "baseline",
            "threatClassification": "benign",
            "riskScore": 12,
            "description": "Official LIC baseline used as benign insurance reference.",
            "signals": ["baseline_ui", "official_branding", "expected_forms"],
            "evidence": "Legitimate insurance portal baseline.",
        },
        {
            "ucId": "UC40",
            "scenario": "Visual Baseline NSDL",
            "url": "https://www.nsdl.co.in",
            "domain": "www.nsdl.co.in",
            "type": "baseline",
            "attackCategory": "baseline",
            "threatClassification": "benign",
            "riskScore": 13,
            "description": "Official NSDL baseline with expected certificate and structure.",
            "signals": ["baseline_ui", "gov_adjacent_trust", "stable_layout"],
            "evidence": "Legitimate baseline for tax-related lookalike checks.",
        },
        {
            "ucId": "UC41",
            "scenario": "Visual Baseline GST",
            "url": "https://www.gst.gov.in",
            "domain": "www.gst.gov.in",
            "type": "baseline",
            "attackCategory": "baseline",
            "threatClassification": "benign",
            "riskScore": 13,
            "description": "Official GST portal baseline with expected government structure.",
            "signals": ["gov_baseline", "expected_dom_structure", "authentic_assets"],
            "evidence": "Legitimate government baseline sample.",
        },
        {
            "ucId": "UC42",
            "scenario": "Compromised News Widget Injection",
            "url": "https://regionalnews.example.com?widget=compromised",
            "domain": "regionalnews.example.com",
            "type": "watering_hole_diff",
            "attackCategory": "watering_hole",
            "threatClassification": "suspicious",
            "riskScore": 80,
            "description": "Compromised variant loading hidden external tracker script.",
            "signals": ["script_injection", "hidden_loader", "unexpected_external_calls"],
            "evidence": "DOM and runtime behavior differ from benign baseline snapshot.",
        },
    ]
)

INFRASTRUCTURE_INTEL.extend(
    [
        {
            "ucId": "UC43",
            "domain": "redirect-voucher-gateway.com",
            "status": "active",
            "hostingProvider": "m247",
            "asn": "AS9009",
            "attackCategory": "redirect_chain",
            "threatClassification": "suspicious",
            "scenario": "Coupon Redirect Broker",
        },
        {
            "ucId": "UC44",
            "domain": "secure-session-checker.net",
            "status": "active",
            "hostingProvider": "unknown-vps",
            "asn": "AS48031",
            "attackCategory": "tls_anomaly",
            "threatClassification": "suspicious",
            "scenario": "Certificate Mismatch Infrastructure",
        },
        {
            "ucId": "UC45",
            "domain": "pre-auth-traffic-gate.com",
            "status": "active",
            "hostingProvider": "choopa",
            "asn": "AS20473",
            "attackCategory": "redirect_chain",
            "threatClassification": "suspicious",
            "scenario": "Pre-Auth Redirect Gate",
        },
        {
            "ucId": "UC46",
            "domain": "cdn-js-hotfix-delivery.net",
            "status": "active",
            "hostingProvider": "ovh",
            "asn": "AS16276",
            "attackCategory": "supply_chain",
            "threatClassification": "suspicious",
            "scenario": "Suspicious CDN Patch Channel",
        },
        {
            "ucId": "UC47",
            "domain": "task-sync-control-panel.top",
            "status": "fast-flux",
            "hostingProvider": "distributed-botnet",
            "asn": "AS-MULTIPLE",
            "attackCategory": "command_and_control",
            "threatClassification": "c2",
            "scenario": "Tasking C2 Panel",
        },
        {
            "ucId": "UC48",
            "domain": "beacon-update-orchestrator.cc",
            "status": "fast-flux",
            "hostingProvider": "residential-proxy",
            "asn": "AS-MULTIPLE",
            "attackCategory": "command_and_control",
            "threatClassification": "c2",
            "scenario": "Beacon Orchestrator",
        },
    ]
)

BEHAVIOR_METRICS.extend(
    [
        {
            "ucId": "UC49",
            "domain": "task-sync-control-panel.top",
            "url": "https://task-sync-control-panel.top/api/pulse",
            "requestsPerMinute": 320.0,
            "errorRate5xx": 0.01,
            "avgTimeBetweenRequests": 7.5,
            "anomalyType": "periodic_beaconing",
            "threatClassification": "c2",
            "isAnomaly": True,
            "scenario": "Behavior C2 Beaconing",
        }
    ]
)


def compute_label_distribution(*datasets: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for docs in datasets:
        for d in docs:
            label = d.get("threatClassification", "unlabeled")
            counts[label] = counts.get(label, 0) + 1
    return counts


async def seed_vector_collection(db, collection_name: str, docs: list[dict], model: str, content_key: str):
    coll = db[collection_name]
    logger.info("Seeding %s (%d docs)", collection_name, len(docs))

    embedding_inputs = []
    for d in docs:
        emb_text = fixed_embedding_text(
            uc_id=d["ucId"],
            collection_name=collection_name,
            scenario=d["scenario"],
            url=d.get("url", ""),
            domain=d.get("domain", ""),
            threat_class=d.get("threatClassification", "unknown"),
            attack_category=d.get("attackCategory", "unknown"),
            signals=d.get("signals", []),
            evidence=d.get("evidence", d.get(content_key, "")),
        )
        d["embeddingInput"] = emb_text
        embedding_inputs.append(emb_text)

    embeddings = await get_batch_embeddings(embedding_inputs, model=model)
    now = datetime.utcnow()

    for d, emb in zip(docs, embeddings):
        d["embedding"] = emb
        d["seedProfile"] = "minimal_fixed_uc"
        d["createdAt"] = now
        d["updatedAt"] = now
        await coll.update_one({"ucId": d["ucId"]}, {"$set": d}, upsert=True)

    logger.info("Seeded %s with fixed-format embeddings", collection_name)


async def seed_search_collection(db, collection_name: str, docs: list[dict]):
    coll = db[collection_name]
    logger.info("Seeding %s (%d docs)", collection_name, len(docs))
    now = datetime.utcnow()
    for d in docs:
        d["seedProfile"] = "minimal_fixed_uc"
        d["createdAt"] = now
        d["updatedAt"] = now
        await coll.update_one({"ucId": d["ucId"]}, {"$set": d}, upsert=True)
    logger.info("Seeded %s", collection_name)


async def clear_collections(db):
    for name in [
        "threat_signals",
        "regional_threats",
        "visual_intelligence",
        "infrastructure_intel",
        "behavior_metrics",
    ]:
        res = await db[name].delete_many({})
        logger.info("Cleared %s (%d deleted)", name, res.deleted_count)


async def seed_minimal_dataset():
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    try:
        logger.info("=" * 72)
        logger.info("Seeding fixed-format UC dataset with targeted expansion")
        logger.info("=" * 72)

        await clear_collections(db)

        await seed_vector_collection(
            db,
            "threat_signals",
            THREAT_SIGNALS,
            model=VoyageModel.LARGE.value,
            content_key="evidence",
        )
        await seed_vector_collection(
            db,
            "regional_threats",
            REGIONAL_THREATS,
            model=VoyageModel.MULTILINGUAL.value,
            content_key="originalText",
        )
        await seed_vector_collection(
            db,
            "visual_intelligence",
            VISUAL_INTELLIGENCE,
            model=VoyageModel.LARGE.value,
            content_key="description",
        )

        await seed_search_collection(db, "infrastructure_intel", INFRASTRUCTURE_INTEL)
        await seed_search_collection(db, "behavior_metrics", BEHAVIOR_METRICS)

        total = (
            len(THREAT_SIGNALS)
            + len(REGIONAL_THREATS)
            + len(VISUAL_INTELLIGENCE)
            + len(INFRASTRUCTURE_INTEL)
            + len(BEHAVIOR_METRICS)
        )
        label_dist = compute_label_distribution(
            THREAT_SIGNALS,
            REGIONAL_THREATS,
            VISUAL_INTELLIGENCE,
            INFRASTRUCTURE_INTEL,
            BEHAVIOR_METRICS,
        )
        logger.info("Done. Seeded %d curated records (UC01-UC49).", total)
        logger.info("Profile tag: seedProfile=minimal_fixed_uc")
        logger.info("Label distribution: %s", label_dist)
    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(seed_minimal_dataset())
