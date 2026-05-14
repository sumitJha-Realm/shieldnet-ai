"""Seed script for multi-collection threat detection data (25 UC coverage).

Seeds 5 collections:
- threat_signals (vector search - voyage-3-large) — UC 1,3,4,7,8,11,12,13,14,19,22,23
- infrastructure_intel (Atlas Search only) — UC 2,5,16,17,22
- regional_threats (vector search - voyage-multilingual-2) — UC 18,24
- visual_intelligence (vector search - voyage-multimodal-3) — UC 10,11,21
- behavior_metrics (Atlas Search only) — UC 9,20,25

Usage:
    python -m scripts.seed_multi_collections
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timedelta

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from motor.motor_asyncio import AsyncIOMotorClient
from services.embedding_service import (
    get_embedding,
    get_multilingual_embedding,
    get_visual_embedding,
    get_batch_embeddings,
    VoyageModel,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT SIGNALS (voyage-3-large embeddings)
# ─────────────────────────────────────────────────────────────────────────────

THREAT_SIGNALS = [
    # UC 1: Typosquatting
    {
        "url": "https://sbi-secure-login.com/verify",
        "domain": "sbi-secure-login.com",
        "docType": "threat_signal",
        "attackCategory": "typosquatting",
        "threatClassification": "phishing",
        "summaryText": "Typosquatting attack impersonating State Bank of India. Domain sbi-secure-login.com registered 3 days ago. Contains login form targeting SBI NetBanking credentials. Edit distance 2 from legitimate onlinesbi.com.",
        "source": "scanner",
        "riskScore": 92,
        "relatedDomains": ["onlinesbi.com", "sbi.co.in"],
        "indicators": {"editDistance": 2, "targetBrand": "SBI", "hasLoginForm": True},
    },
    # UC 3: Phishing URL ID
    {
        "url": "https://secure-hdfc-banking.in/netbanking/login",
        "domain": "secure-hdfc-banking.in",
        "docType": "threat_signal",
        "attackCategory": "phishing",
        "threatClassification": "phishing",
        "summaryText": "Phishing URL targeting HDFC Bank customers. Mimics HDFC NetBanking login page with OTP verification step. Domain registered on bulletproof hosting in Russia. SSL certificate from Let's Encrypt issued 1 day ago.",
        "source": "scanner",
        "riskScore": 95,
        "relatedDomains": ["hdfcbank.com", "netbanking.hdfcbank.com"],
        "indicators": {"hasOtpField": True, "targetBrand": "HDFC", "hostingGeo": "RU"},
    },
    # UC 4: Threat Intel Feed (PhishTank)
    {
        "url": "https://login-microsoft365-verify.com/auth",
        "domain": "login-microsoft365-verify.com",
        "docType": "threat_intel",
        "attackCategory": "credential_harvesting",
        "threatClassification": "phishing",
        "summaryText": "PhishTank verified phishing URL targeting Microsoft 365 credentials. Active campaign using Google Ads for distribution. First reported 6 hours ago with 47 independent reports. Kit uses real-time relay to bypass MFA.",
        "source": "phishtank_feed",
        "riskScore": 99,
        "relatedDomains": ["login.microsoftonline.com", "outlook.office365.com"],
        "feedMetadata": {"feedName": "PhishTank", "reportCount": 47, "verified": True, "phishtankId": "PT-2026-847291"},
    },
    # UC 4: CERT-In Advisory
    {
        "url": "https://aadhaar-update-portal.in/ekyc",
        "domain": "aadhaar-update-portal.in",
        "docType": "threat_intel",
        "attackCategory": "government_impersonation",
        "threatClassification": "phishing",
        "summaryText": "CERT-In advisory CI-2026-0412: Active campaign impersonating UIDAI Aadhaar update portal. Harvesting Aadhaar numbers and OTPs. Multiple domains registered in last 48 hours. Targets include DigiLocker and UIDAI services.",
        "source": "cert_in_feed",
        "riskScore": 97,
        "relatedDomains": ["uidai.gov.in", "digilocker.gov.in", "eaadhaar.uidai.gov.in"],
        "feedMetadata": {"feedName": "CERT-In", "advisoryId": "CI-2026-0412", "severity": "HIGH"},
    },
    # UC 7: Homoglyph/IDN
    {
        "url": "https://xn--gogle-mra.com/login",
        "domain": "xn--gogle-mra.com",
        "docType": "threat_signal",
        "attackCategory": "homoglyph_attack",
        "threatClassification": "phishing",
        "summaryText": "IDN homoglyph attack using Cyrillic characters to impersonate google.com. Punycode domain xn--gogle-mra.com renders as googlе.com (Cyrillic 'е'). Hosts credential harvesting page mimicking Google login.",
        "source": "scanner",
        "riskScore": 94,
        "relatedDomains": ["google.com", "accounts.google.com"],
        "indicators": {"homoglyphType": "cyrillic_e", "targetBrand": "Google", "visualSimilarity": 0.98},
    },
    # UC 8: URL Shortener Abuse
    {
        "url": "https://bit.ly/3xR7kQm",
        "domain": "bit.ly",
        "docType": "threat_signal",
        "attackCategory": "shortener_abuse",
        "threatClassification": "phishing",
        "summaryText": "URL shortener abuse detected. bit.ly/3xR7kQm resolves to paytm-kyc-verify.in credential harvesting page. Short URL distributed via WhatsApp messages claiming Paytm KYC deadline. Redirect chain bypasses URL reputation checks.",
        "source": "scanner",
        "riskScore": 88,
        "relatedDomains": ["paytm.com", "paytm-kyc-verify.in"],
        "indicators": {"shortener": "bit.ly", "resolvedDomain": "paytm-kyc-verify.in", "distributionMethod": "whatsapp"},
    },
    # UC 8: Alternate shortener abuse
    {
        "url": "https://tinyurl.com/pan-urgent-link",
        "domain": "tinyurl.com",
        "docType": "threat_signal",
        "attackCategory": "shortener_abuse",
        "threatClassification": "phishing",
        "summaryText": "URL shortener abuse detected. tinyurl.com/pan-urgent-link resolves to aadhaar-link-pan.in/update government impersonation page. Short link spread through SMS messages warning that PAN will be disabled without immediate Aadhaar linking.",
        "source": "scanner",
        "riskScore": 90,
        "relatedDomains": ["incometax.gov.in", "aadhaar-link-pan.in"],
        "indicators": {"shortener": "tinyurl.com", "resolvedDomain": "aadhaar-link-pan.in", "distributionMethod": "sms"},
    },
    # UC 8/23: Resolved short-link target
    {
        "url": "https://paytm-kyc-verify.in/login",
        "domain": "paytm-kyc-verify.in",
        "docType": "threat_signal",
        "attackCategory": "credential_harvesting",
        "threatClassification": "phishing",
        "summaryText": "Credential harvesting page targeting Paytm users. Landing page reached via shortened links and QR posters. Requests Paytm mobile number, OTP, and debit card details under the pretext of mandatory KYC refresh.",
        "source": "scanner",
        "riskScore": 93,
        "relatedDomains": ["paytm.com", "bit.ly/3xR7kQm"],
        "indicators": {"targetBrand": "Paytm", "hasOtpField": True, "distributionMethod": "shortener_and_qr"},
    },
    # UC 11: Brand Impersonation
    {
        "url": "https://icici-bank-rewards.com/claim",
        "domain": "icici-bank-rewards.com",
        "docType": "threat_signal",
        "attackCategory": "brand_impersonation",
        "threatClassification": "phishing",
        "summaryText": "Brand impersonation of ICICI Bank. Domain icici-bank-rewards.com uses official ICICI branding and color scheme. Offers fake reward points claim to harvest credit card details. Registered in Philippines 2 days ago.",
        "source": "scanner",
        "riskScore": 91,
        "relatedDomains": ["icicibank.com", "icicibank.co.in"],
        "indicators": {"targetBrand": "ICICI", "usesOfficialLogo": True, "registrarCountry": "PH"},
    },
    # UC 12: Malware Distribution
    {
        "url": "https://free-software-download.xyz/adobe-reader-update.exe",
        "domain": "free-software-download.xyz",
        "docType": "threat_signal",
        "attackCategory": "malware_distribution",
        "threatClassification": "malware",
        "summaryText": "Malware distribution site disguising trojan as Adobe Reader update. Executable adobe-reader-update.exe contains banking trojan BankBot variant. Domain uses .xyz TLD registered 1 day ago. Distributed via popup ads on torrent sites.",
        "source": "scanner",
        "riskScore": 96,
        "relatedDomains": ["adobe.com", "get.adobe.com"],
        "indicators": {"malwareFamily": "BankBot", "fileType": "exe", "disguisedAs": "Adobe Reader"},
    },
    # UC 13: Threat Intel Cross-Ref (C2 server)
    {
        "url": "http://45.33.32.156:8080/beacon",
        "domain": "45.33.32.156",
        "docType": "threat_intel",
        "attackCategory": "c2_server",
        "threatClassification": "c2",
        "summaryText": "AlienVault OTX: IP 45.33.32.156 confirmed C2 server for BankBot banking trojan. 12 malicious domains resolving to this IP in last 24 hours. Infrastructure shared with sbi-secure-login.com phishing campaign.",
        "source": "otx_feed",
        "riskScore": 96,
        "relatedDomains": ["sbi-secure-login.com", "hdfc-secure-update.in"],
        "feedMetadata": {"feedName": "AlienVault OTX", "pulseId": "OTX-65f8a2b1", "malwareFamily": "BankBot"},
    },
    # UC 14: Campaign Clustering
    {
        "url": "https://sbi-netbanking-update.in/verify",
        "domain": "sbi-netbanking-update.in",
        "docType": "threat_signal",
        "attackCategory": "coordinated_campaign",
        "threatClassification": "phishing",
        "summaryText": "Part of coordinated SBI phishing campaign cluster (Campaign-SBI-2026-05). Shares infrastructure with 8 other domains. Common registration pattern: registered via same registrar within 48-hour window. Identical page template.",
        "source": "campaign_detection",
        "riskScore": 93,
        "relatedDomains": ["sbi-secure-login.com", "sbi-kyc-update.in", "sbi-otp-verify.com"],
        "campaignId": "campaign-sbi-2026-05",
        "indicators": {"clusterSize": 8, "sharedRegistrar": True, "sharedTemplate": True},
    },
    # UC 19: Dark Web Intel
    {
        "url": "http://darkmarket7xj3.onion/phishing-kits/sbi-clone",
        "domain": "darkmarket7xj3.onion",
        "docType": "dark_web_intel",
        "attackCategory": "phishing_kit_sale",
        "threatClassification": "credential_harvesting",
        "summaryText": "Dark web marketplace selling SBI phishing kit clone with SMS OTP bypass. Kit includes replica login page, card entry form, and Telegram exfiltration bot. Targets Indian banking customers. Price 5000 INR. Linked to sbi-secure-login.com.",
        "source": "dark_web_monitor",
        "riskScore": 95,
        "relatedDomains": ["sbi-secure-login.com", "sbi-kyc-verify.in"],
        "indicators": {"kitIncludes": ["login_page", "otp_page", "card_form"], "exfilMethod": "telegram_bot", "targetBrands": ["SBI", "HDFC", "ICICI"]},
    },
    # UC 19: Dark Web Leaked Credentials
    {
        "url": "http://leakforum2abc.onion/dumps/gov-in-emails",
        "domain": "leakforum2abc.onion",
        "docType": "dark_web_intel",
        "attackCategory": "data_leak",
        "threatClassification": "credential_harvesting",
        "summaryText": "Forum post advertising leaked government email credentials from nic.in and gov.in domains. 50,000 records claimed. Linked to phishing campaign targeting NIC webmail. Active bidding with 12 interested buyers.",
        "source": "dark_web_monitor",
        "riskScore": 92,
        "relatedDomains": ["nic-webmail-login.com", "govmail-secure.in", "mail.nic.in"],
        "indicators": {"recordCount": 50000, "targetDomains": ["nic.in", "gov.in"], "buyers": 12},
    },
    # UC 22: Supply Chain
    {
        "url": "https://cdn-analytics-lib.com/tracker.js",
        "domain": "cdn-analytics-lib.com",
        "docType": "threat_signal",
        "attackCategory": "supply_chain",
        "threatClassification": "malware",
        "summaryText": "Supply chain compromise: cdn-analytics-lib.com serving backdoored JavaScript library. Injected crypto-mining payload into tracker.js loaded by 200+ government websites. Package mimics legitimate analytics SDK. Active since 48 hours.",
        "source": "supply_chain_monitor",
        "riskScore": 97,
        "relatedDomains": ["analytics-lib.com", "gov.in"],
        "indicators": {"affectedSites": 200, "payloadType": "cryptominer", "injectionMethod": "cdn_compromise"},
    },
    # UC 23: QR Code Phishing
    {
        "url": "https://paytm-kyc-verify.in/update?ref=qr_poster_delhi",
        "domain": "paytm-kyc-verify.in",
        "docType": "threat_signal",
        "attackCategory": "qr_phishing",
        "threatClassification": "phishing",
        "summaryText": "URL extracted from QR code on fake Paytm KYC poster distributed in Delhi NCR metro stations. Resolves to credential harvesting page mimicking Paytm verification. Contains deeplink parameters targeting Paytm app intent.",
        "source": "qr_scan",
        "riskScore": 88,
        "relatedDomains": ["paytm.com"],
        "qrMetadata": {"extractedFrom": "physical_poster", "location": "Delhi NCR", "deepLinkScheme": "paytm://kyc/verify"},
    },
    # UC 23: UPI Fraud
    {
        "url": "upi://pay?pa=fraud@ybl&pn=SBI&am=1&cu=INR",
        "domain": "upi_intent",
        "docType": "threat_signal",
        "attackCategory": "upi_fraud",
        "threatClassification": "phishing",
        "summaryText": "Malicious UPI deep link disguised as SBI payment request. QR code encodes UPI intent with fraudulent VPA fraud@ybl. Distributed via WhatsApp claiming income tax refund. Small amount to test before larger fraud.",
        "source": "qr_scan",
        "riskScore": 91,
        "relatedDomains": ["sbi.co.in"],
        "qrMetadata": {"extractedFrom": "whatsapp_image", "upiVPA": "fraud@ybl", "claimedIdentity": "SBI Tax Refund"},
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE INTEL (Atlas Search only — no embeddings)
# ─────────────────────────────────────────────────────────────────────────────

INFRASTRUCTURE_INTEL = [
    # UC 2: DNS threats
    {
        "domain": "sbi-secure-login.com",
        "ip": "103.21.44.12",
        "asn": "AS13335",
        "asnName": "Cloudflare-Fronted Bulletproof",
        "hostingProvider": "bulletproof-host-ru",
        "status": "active",
        "ipRotationCount24h": 3,
        "ttlSeconds": 300,
        "nsServers": ["ns1.suspicio.us", "ns2.suspicio.us"],
        "mxRecords": [],
        "resolvedIps": ["103.21.44.12", "103.21.44.13"],
        "tlsIssuer": "Let's Encrypt",
        "tlsValidDays": 89,
        "tlsSanMismatch": False,
        "tlsSelfSigned": False,
        "redirectChainLength": 0,
        "redirectDomains": [],
        "geoCountry": "RU",
    },
    # UC 5: Redirect chain infrastructure
    {
        "domain": "click-track-offer.com",
        "ip": "185.220.101.45",
        "asn": "AS9009",
        "asnName": "M247-Hosting",
        "hostingProvider": "m247",
        "status": "active",
        "ipRotationCount24h": 1,
        "ttlSeconds": 3600,
        "nsServers": ["ns1.m247.com"],
        "mxRecords": [],
        "resolvedIps": ["185.220.101.45"],
        "tlsIssuer": "Let's Encrypt",
        "tlsValidDays": 45,
        "tlsSanMismatch": True,
        "tlsSelfSigned": False,
        "redirectChainLength": 5,
        "redirectDomains": ["click-track-offer.com", "redir1.xyz", "redir2.top", "final-phish.in", "sbi-login-verify.com"],
        "geoCountry": "NL",
    },
    # UC 16: TLS Certificate Anomaly
    {
        "domain": "secure-banking-portal.xyz",
        "ip": "91.234.56.78",
        "asn": "AS48031",
        "asnName": "PE-Ivanov",
        "hostingProvider": "unknown-vps",
        "status": "active",
        "ipRotationCount24h": 0,
        "ttlSeconds": 3600,
        "nsServers": ["ns1.reg.ru"],
        "mxRecords": [],
        "resolvedIps": ["91.234.56.78"],
        "tlsIssuer": "self-signed",
        "tlsValidDays": 365,
        "tlsSanMismatch": True,
        "tlsSelfSigned": True,
        "redirectChainLength": 0,
        "redirectDomains": [],
        "geoCountry": "RU",
    },
    # UC 17: Fast-Flux DNS
    {
        "domain": "fast-flux-botnet.top",
        "ip": "dynamic",
        "asn": "AS-MULTIPLE",
        "asnName": "Multiple ASNs",
        "hostingProvider": "distributed-botnet",
        "status": "fast-flux",
        "ipRotationCount24h": 47,
        "ttlSeconds": 60,
        "nsServers": ["ns1.flux-dns.xyz", "ns2.flux-dns.xyz", "ns3.flux-dns.xyz"],
        "mxRecords": [],
        "resolvedIps": ["1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"],
        "tlsIssuer": "none",
        "tlsValidDays": 0,
        "tlsSanMismatch": False,
        "tlsSelfSigned": False,
        "redirectChainLength": 0,
        "redirectDomains": [],
        "geoCountry": "MULTI",
    },
    # UC 17: Fast-Flux variant (banking trojan C2)
    {
        "domain": "update-service-cdn.buzz",
        "ip": "dynamic",
        "asn": "AS-MULTIPLE",
        "asnName": "Botnet Infrastructure",
        "hostingProvider": "residential-proxy",
        "status": "fast-flux",
        "ipRotationCount24h": 23,
        "ttlSeconds": 120,
        "nsServers": ["ns1.bulletproof.cc", "ns2.bulletproof.cc"],
        "mxRecords": [],
        "resolvedIps": ["45.33.32.156", "23.45.67.89", "102.33.44.55"],
        "tlsIssuer": "Let's Encrypt",
        "tlsValidDays": 30,
        "tlsSanMismatch": True,
        "tlsSelfSigned": False,
        "redirectChainLength": 2,
        "redirectDomains": ["update-service-cdn.buzz", "payload-server.top"],
        "geoCountry": "UA",
    },
    # UC 22: Supply chain CDN compromise
    {
        "domain": "cdn-analytics-lib.com",
        "ip": "104.18.22.33",
        "asn": "AS13335",
        "asnName": "Cloudflare",
        "hostingProvider": "cloudflare",
        "status": "active",
        "ipRotationCount24h": 0,
        "ttlSeconds": 300,
        "nsServers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "mxRecords": [],
        "resolvedIps": ["104.18.22.33", "104.18.22.34"],
        "tlsIssuer": "Cloudflare Inc",
        "tlsValidDays": 365,
        "tlsSanMismatch": False,
        "tlsSelfSigned": False,
        "redirectChainLength": 0,
        "redirectDomains": [],
        "cdnProvider": "cloudflare",
        "servesScripts": True,
        "geoCountry": "US",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# REGIONAL THREATS (voyage-multilingual-2 embeddings)
# ─────────────────────────────────────────────────────────────────────────────

REGIONAL_THREATS = [
    # UC 18 & 24: Hindi banking scam
    {
        "url": "https://sbi-kyc-update.in/verify",
        "domain": "sbi-kyc-update.in",
        "language": "hi",
        "originalText": "प्रिय ग्राहक, आपका SBI खाता ब्लॉक हो गया है। तुरंत KYC अपडेट करें अन्यथा 24 घंटे में खाता बंद कर दिया जाएगा। लिंक: sbi-kyc-update.in/verify OTP दर्ज करें।",
        "translatedText": "Dear customer, your SBI account has been blocked. Update KYC immediately or account will be closed in 24 hours. Link: sbi-kyc-update.in/verify Enter OTP.",
        "summaryText": "Hindi language SBI KYC scam message threatening account closure. Urgency tactic with 24-hour deadline. Targets SBI customers via SMS/WhatsApp.",
        "attackCategory": "banking_scam",
        "targetBrand": "SBI",
        "region": "North India",
        "riskScore": 90,
        "source": "regional_monitor",
    },
    # UC 24: Tamil language scam
    {
        "url": "https://epfo-claim-status.in/check",
        "domain": "epfo-claim-status.in",
        "language": "ta",
        "originalText": "உங்கள் EPFO கணக்கில் ₹15,000 நிலுவை உள்ளது. இப்போதே பெற கீழே உள்ள இணைப்பை கிளிக் செய்யவும். ஆதார் எண் மற்றும் வங்கி விவரங்களை உள்ளிடவும்.",
        "translatedText": "Your EPFO account has ₹15,000 pending. Click the link below to receive it now. Enter Aadhaar number and bank details.",
        "summaryText": "Tamil language EPFO withdrawal scam. Claims pending balance to lure victims into entering Aadhaar and bank details. Targets Tamil Nadu workers.",
        "attackCategory": "government_impersonation",
        "targetBrand": "EPFO",
        "region": "Tamil Nadu",
        "riskScore": 87,
        "source": "regional_monitor",
    },
    # UC 24: Bengali scam
    {
        "url": "https://pm-kisan-samman.in/apply",
        "domain": "pm-kisan-samman.in",
        "language": "bn",
        "originalText": "প্রিয় কৃষক, আপনার PM-KISAN ₹6000 জমা হয়েছে। এখনই নিন - pm-kisan-samman.in/apply আধার নম্বর ও ব্যাঙ্ক তথ্য দিন।",
        "translatedText": "Dear farmer, your PM-KISAN ₹6000 has been deposited. Collect now - pm-kisan-samman.in/apply Enter Aadhaar number and bank details.",
        "summaryText": "Bengali language PM-KISAN scheme fraud. Impersonates government agricultural subsidy program. Targets farmers in West Bengal with false deposit claim.",
        "attackCategory": "government_impersonation",
        "targetBrand": "PM-KISAN",
        "region": "West Bengal",
        "riskScore": 86,
        "source": "regional_monitor",
    },
    # UC 18: Hindi Aadhaar scam
    {
        "url": "https://aadhaar-link-pan.in/update",
        "domain": "aadhaar-link-pan.in",
        "language": "hi",
        "originalText": "आयकर विभाग: आपका PAN आधार से लिंक नहीं है। तुरंत लिंक करें अन्यथा PAN निष्क्रिय हो जाएगा। aadhaar-link-pan.in/update पर जाएं।",
        "translatedText": "Income Tax Department: Your PAN is not linked with Aadhaar. Link immediately or PAN will be deactivated. Visit aadhaar-link-pan.in/update.",
        "summaryText": "Hindi language PAN-Aadhaar linking scam impersonating Income Tax Department. Uses regulatory deadline threat to create urgency. Harvests PAN and Aadhaar numbers.",
        "attackCategory": "government_impersonation",
        "targetBrand": "Income Tax Department",
        "region": "Pan India",
        "riskScore": 91,
        "source": "regional_monitor",
    },
    # UC 24: Tamil EPFO variant for stronger multilingual clustering
    {
        "url": "https://epfo-withdrawal-alert.in/redeem",
        "domain": "epfo-withdrawal-alert.in",
        "language": "ta",
        "originalText": "உங்கள் EPFO தொகை உடனே பெற தயாராக உள்ளது. KYC சரிபார்க்க இந்த இணைப்பை பயன்படுத்தவும். ஆதார் எண், வங்கி கணக்கு மற்றும் OTP ஐ பதிவுசெய்யவும்.",
        "translatedText": "Your EPFO amount is ready for immediate withdrawal. Use this link to verify KYC. Enter Aadhaar number, bank account, and OTP.",
        "summaryText": "Tamil language EPFO payout scam using fake KYC verification. Harvests Aadhaar, bank account, and OTP details. Targets salaried workers in Tamil Nadu.",
        "attackCategory": "government_impersonation",
        "targetBrand": "EPFO",
        "region": "Tamil Nadu",
        "riskScore": 89,
        "source": "regional_monitor",
    },
    # UC 24: Bengali PM-KISAN variant for stronger multilingual clustering
    {
        "url": "https://pm-kisan-bonus.in/claim",
        "domain": "pm-kisan-bonus.in",
        "language": "bn",
        "originalText": "সরকারি PM-KISAN বোনাস আপনার জন্য অনুমোদিত হয়েছে। টাকা তুলতে এখনই এই লিঙ্কে যান এবং আধার ও ব্যাঙ্ক তথ্য দিন।",
        "translatedText": "Government PM-KISAN bonus has been approved for you. Visit this link now to withdraw funds and enter Aadhaar and bank details.",
        "summaryText": "Bengali PM-KISAN bonus scam impersonating a government subsidy disbursement. Uses payout lure to capture Aadhaar and bank information from farmers.",
        "attackCategory": "government_impersonation",
        "targetBrand": "PM-KISAN",
        "region": "West Bengal",
        "riskScore": 88,
        "source": "regional_monitor",
    },
    # UC 18/24: Hindi tax refund variant for stronger government-impersonation clustering
    {
        "url": "https://income-tax-refund-alert.in/claim",
        "domain": "income-tax-refund-alert.in",
        "language": "hi",
        "originalText": "आयकर विभाग से सूचना: आपका रिफंड लंबित है। तुरंत दावा करें नहीं तो भुगतान रद्द हो जाएगा। लिंक खोलें और PAN, आधार और बैंक विवरण भरें।",
        "translatedText": "Notice from the Income Tax Department: your refund is pending. Claim immediately or payment will be cancelled. Open the link and submit PAN, Aadhaar, and bank details.",
        "summaryText": "Hindi income-tax refund scam impersonating tax authorities. Uses refund urgency to capture PAN, Aadhaar, and bank account details.",
        "attackCategory": "government_impersonation",
        "targetBrand": "Income Tax Department",
        "region": "Pan India",
        "riskScore": 90,
        "source": "regional_monitor",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# VISUAL INTELLIGENCE (voyage-multimodal-3 embeddings)
# ─────────────────────────────────────────────────────────────────────────────

VISUAL_INTELLIGENCE = [
    # UC 10: Credential harvesting page (baseline comparison)
    {
        "url": "https://onlinesbi.sbi",
        "domain": "onlinesbi.sbi",
        "type": "baseline",
        "brandName": "SBI",
        "description": "Official State Bank of India online banking login page. Blue header with SBI logo. Username and password fields with CAPTCHA. Security notice at bottom. Footer with RBI disclaimer.",
        "similarityToBaseline": 1.0,
    },
    {
        "url": "https://sbi-secure-login.com/verify",
        "domain": "sbi-secure-login.com",
        "type": "phishing_capture",
        "brandName": "SBI",
        "description": "Phishing page mimicking SBI online banking. Near-identical blue header but slightly different shade. Missing CAPTCHA. Extra OTP field not present in original. No RBI disclaimer in footer. Telegram exfil script detected.",
        "similarityToBaseline": 0.89,
    },
    # UC 11: Brand impersonation visual
    {
        "url": "https://hdfcbank.com",
        "domain": "hdfcbank.com",
        "type": "baseline",
        "brandName": "HDFC",
        "description": "Official HDFC Bank homepage. Dark blue navigation bar with HDFC logo. Personal Banking, NRI Banking tabs. Login button top-right. Red and blue color scheme. Security awareness banner.",
        "similarityToBaseline": 1.0,
    },
    {
        "url": "https://secure-hdfc-banking.in/netbanking/login",
        "domain": "secure-hdfc-banking.in",
        "type": "phishing_capture",
        "brandName": "HDFC",
        "description": "Phishing page impersonating HDFC Bank. Uses HDFC logo and blue color scheme. Login form requests Customer ID, IPIN, and mobile number. Missing security awareness content. URL bar shows non-HDFC domain.",
        "similarityToBaseline": 0.85,
    },
    # UC 21: Watering hole detection (before/after)
    {
        "url": "https://eprocure.gov.in",
        "domain": "eprocure.gov.in",
        "type": "baseline",
        "brandName": "Government eProcurement",
        "description": "Official Government eProcurement portal. Standard NIC header with emblem. Tender search form. Registration links. Clean layout without external scripts or iframes. Standard government footer.",
        "similarityToBaseline": 1.0,
    },
    {
        "url": "https://eprocure.gov.in",
        "domain": "eprocure.gov.in",
        "type": "watering_hole_diff",
        "brandName": "Government eProcurement",
        "description": "COMPROMISED: Government eProcurement portal with injected invisible iframe loading malware from cdn-analytics-lib.com. Visual appearance unchanged but DOM contains additional script tags. Background cryptocurrency miner active.",
        "similarityToBaseline": 0.72,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# BEHAVIOR METRICS (Atlas Search only — no embeddings)
# ─────────────────────────────────────────────────────────────────────────────

BEHAVIOR_METRICS = [
    # UC 20: Bot detection — credential stuffing
    {
        "domain": "sbi-secure-login.com",
        "url": "https://sbi-secure-login.com/verify",
        "requestsPerMinute": 450.0,
        "uniqueIps": 3,
        "avgResponseTimeMs": 12.5,
        "errorRate4xx": 0.85,
        "errorRate5xx": 0.02,
        "headerEntropy": 0.08,
        "avgTimeBetweenRequests": 15.0,
        "userAgentVariety": 1,
        "hasCaptchaBypass": True,
        "isAnomaly": True,
        "anomalyType": "credential_stuffing",
        "zScoreRpm": 4.2,
        "zScoreErrorRate": 3.8,
    },
    # UC 20: API abuse
    {
        "domain": "api.govservice.in",
        "url": "https://api.govservice.in/v1/citizen/lookup",
        "requestsPerMinute": 2000.0,
        "uniqueIps": 1,
        "avgResponseTimeMs": 5.2,
        "errorRate4xx": 0.15,
        "errorRate5xx": 0.0,
        "headerEntropy": 0.03,
        "avgTimeBetweenRequests": 3.0,
        "userAgentVariety": 1,
        "hasCaptchaBypass": False,
        "isAnomaly": True,
        "anomalyType": "api_scraping",
        "zScoreRpm": 8.5,
        "zScoreErrorRate": 1.2,
    },
    # UC 25: Traffic anomaly — sudden spike
    {
        "domain": "income-tax-refund.in",
        "url": "https://income-tax-refund.in/claim",
        "requestsPerMinute": 800.0,
        "uniqueIps": 15000,
        "avgResponseTimeMs": 250.0,
        "errorRate4xx": 0.02,
        "errorRate5xx": 0.45,
        "headerEntropy": 0.72,
        "avgTimeBetweenRequests": 75.0,
        "userAgentVariety": 45,
        "hasCaptchaBypass": False,
        "isAnomaly": True,
        "anomalyType": "traffic_spike",
        "zScoreRpm": 6.1,
        "zScoreErrorRate": 5.3,
    },
    # UC 25: Behavioral anomaly — low-and-slow attack
    {
        "domain": "secure-banking-portal.xyz",
        "url": "https://secure-banking-portal.xyz/admin",
        "requestsPerMinute": 12.0,
        "uniqueIps": 50,
        "avgResponseTimeMs": 890.0,
        "errorRate4xx": 0.45,
        "errorRate5xx": 0.0,
        "headerEntropy": 0.15,
        "avgTimeBetweenRequests": 5000.0,
        "userAgentVariety": 2,
        "hasCaptchaBypass": False,
        "isAnomaly": True,
        "anomalyType": "brute_force_slow",
        "zScoreRpm": 0.5,
        "zScoreErrorRate": 4.1,
    },
    # UC 9: Bulk scan results pattern
    {
        "domain": "bulk-scan-batch-2026-05-14",
        "url": None,
        "requestsPerMinute": 20.0,
        "uniqueIps": 1,
        "avgResponseTimeMs": 350.0,
        "errorRate4xx": 0.0,
        "errorRate5xx": 0.0,
        "headerEntropy": 0.9,
        "avgTimeBetweenRequests": 3000.0,
        "userAgentVariety": 1,
        "hasCaptchaBypass": False,
        "isAnomaly": False,
        "anomalyType": "soc_batch_scan",
        "zScoreRpm": 0.0,
        "zScoreErrorRate": 0.0,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# SEED EXECUTION
# ─────────────────────────────────────────────────────────────────────────────


async def seed_threat_signals(db):
    """Seed threat_signals with voyage-3-large embeddings."""
    coll = db["threat_signals"]
    logger.info("Seeding threat_signals (%d documents)...", len(THREAT_SIGNALS))

    # Generate embeddings in batch
    texts = [doc["summaryText"] for doc in THREAT_SIGNALS]
    try:
        embeddings = await get_batch_embeddings(texts, model=VoyageModel.LARGE.value)
    except Exception as e:
        logger.error("Failed to generate threat embeddings: %s", e)
        logger.info("Seeding without embeddings (indexes won't work for vector search)")
        embeddings = [None] * len(THREAT_SIGNALS)

    now = datetime.utcnow()
    for doc, emb in zip(THREAT_SIGNALS, embeddings):
        doc["embedding"] = emb
        doc["createdAt"] = now
        doc["discoveredAt"] = now - timedelta(hours=len(THREAT_SIGNALS))
        await coll.update_one(
            {"url": doc["url"], "attackCategory": doc.get("attackCategory", "")},
            {"$set": doc},
            upsert=True,
        )

    logger.info("✓ threat_signals seeded: %d documents", len(THREAT_SIGNALS))


async def seed_infrastructure_intel(db):
    """Seed infrastructure_intel (no embeddings — Atlas Search only)."""
    coll = db["infrastructure_intel"]
    logger.info("Seeding infrastructure_intel (%d documents)...", len(INFRASTRUCTURE_INTEL))

    now = datetime.utcnow()
    for doc in INFRASTRUCTURE_INTEL:
        doc["firstSeenAt"] = now - timedelta(days=3)
        doc["lastSeenAt"] = now
        doc["createdAt"] = now
        await coll.update_one(
            {"domain": doc["domain"]},
            {"$set": doc},
            upsert=True,
        )

    logger.info("✓ infrastructure_intel seeded: %d documents", len(INFRASTRUCTURE_INTEL))


async def seed_regional_threats(db):
    """Seed regional_threats with voyage-multilingual-2 embeddings."""
    coll = db["regional_threats"]
    logger.info("Seeding regional_threats (%d documents)...", len(REGIONAL_THREATS))

    # Generate multilingual embeddings (use originalText for native language encoding)
    texts = [doc["originalText"] or doc["summaryText"] for doc in REGIONAL_THREATS]
    try:
        embeddings = await get_batch_embeddings(texts, model=VoyageModel.MULTILINGUAL.value)
    except Exception as e:
        logger.error("Failed to generate multilingual embeddings: %s", e)
        embeddings = [None] * len(REGIONAL_THREATS)

    now = datetime.utcnow()
    for doc, emb in zip(REGIONAL_THREATS, embeddings):
        doc["embedding"] = emb
        doc["createdAt"] = now
        await coll.update_one(
            {"url": doc["url"], "language": doc.get("language", "hi")},
            {"$set": doc},
            upsert=True,
        )

    logger.info("✓ regional_threats seeded: %d documents", len(REGIONAL_THREATS))


async def seed_visual_intelligence(db):
    """Seed visual_intelligence with voyage-multimodal-3 embeddings."""
    coll = db["visual_intelligence"]
    logger.info("Seeding visual_intelligence (%d documents)...", len(VISUAL_INTELLIGENCE))

    # Generate visual embeddings from text descriptions
    # Use voyage-4-large (multimodal not available on Atlas endpoint for batch text)
    texts = [doc["description"] for doc in VISUAL_INTELLIGENCE]
    try:
        embeddings = await get_batch_embeddings(texts, model=VoyageModel.MULTILINGUAL.value)
    except Exception as e:
        logger.error("Failed to generate visual embeddings: %s", e)
        embeddings = [None] * len(VISUAL_INTELLIGENCE)

    now = datetime.utcnow()
    for doc, emb in zip(VISUAL_INTELLIGENCE, embeddings):
        doc["embedding"] = emb
        doc["capturedAt"] = now - timedelta(hours=2)
        doc["createdAt"] = now
        doc["screenshotHash"] = ""  # POC: no actual screenshots
        await coll.update_one(
            {"url": doc["url"], "type": doc.get("type", "baseline")},
            {"$set": doc},
            upsert=True,
        )

    logger.info("✓ visual_intelligence seeded: %d documents", len(VISUAL_INTELLIGENCE))


async def seed_behavior_metrics(db):
    """Seed behavior_metrics (no embeddings — Atlas Search only)."""
    coll = db["behavior_metrics"]
    logger.info("Seeding behavior_metrics (%d documents)...", len(BEHAVIOR_METRICS))

    now = datetime.utcnow()
    for doc in BEHAVIOR_METRICS:
        doc["windowStart"] = now - timedelta(minutes=15)
        doc["windowEnd"] = now
        doc["createdAt"] = now
        await coll.update_one(
            {"domain": doc["domain"], "anomalyType": doc.get("anomalyType", "")},
            {"$set": doc},
            upsert=True,
        )

    logger.info("✓ behavior_metrics seeded: %d documents", len(BEHAVIOR_METRICS))


async def create_indexes(db):
    """Create MongoDB indexes for all collections.
    Note: Atlas Search and Vector Search indexes must be created via Atlas UI/API."""
    logger.info("Creating standard MongoDB indexes...")

    # threat_signals
    coll = db["threat_signals"]
    await coll.create_index("url")
    await coll.create_index("domain")
    await coll.create_index("attackCategory")
    await coll.create_index("source")
    await coll.create_index("createdAt")

    # infrastructure_intel
    coll = db["infrastructure_intel"]
    await coll.create_index("domain", unique=True)
    await coll.create_index("asn")
    await coll.create_index("status")
    await coll.create_index("ipRotationCount24h")

    # regional_threats
    coll = db["regional_threats"]
    await coll.create_index("url")
    await coll.create_index("language")
    await coll.create_index("region")

    # visual_intelligence
    coll = db["visual_intelligence"]
    await coll.create_index("url")
    await coll.create_index("brandName")
    await coll.create_index("type")

    # behavior_metrics
    coll = db["behavior_metrics"]
    await coll.create_index("domain")
    await coll.create_index("anomalyType")
    await coll.create_index("isAnomaly")
    await coll.create_index("requestsPerMinute")

    logger.info("✓ Standard indexes created")


async def main():
    """Main seed function."""
    logger.info("=" * 60)
    logger.info("ShieldNet-AI Multi-Collection Seed Script")
    logger.info("Covering all 25 Use Cases")
    logger.info("=" * 60)

    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    try:
        # Create standard indexes first
        await create_indexes(db)

        # Seed all collections
        await seed_threat_signals(db)
        await seed_infrastructure_intel(db)
        await seed_regional_threats(db)
        await seed_visual_intelligence(db)
        await seed_behavior_metrics(db)

        logger.info("=" * 60)
        logger.info("SEED COMPLETE — Summary:")
        logger.info("  threat_signals:       %d docs (voyage-3-large embeddings)", len(THREAT_SIGNALS))
        logger.info("  infrastructure_intel: %d docs (no embeddings)", len(INFRASTRUCTURE_INTEL))
        logger.info("  regional_threats:     %d docs (voyage-multilingual-2 embeddings)", len(REGIONAL_THREATS))
        logger.info("  visual_intelligence:  %d docs (voyage-multimodal-3 embeddings)", len(VISUAL_INTELLIGENCE))
        logger.info("  behavior_metrics:     %d docs (no embeddings)", len(BEHAVIOR_METRICS))
        logger.info("=" * 60)
        logger.info("")
        logger.info("NEXT STEPS:")
        logger.info("  1. Create Atlas Search indexes via Atlas UI:")
        logger.info("     - infrastructure_intel: 'infra_search_index' (compound on domain, asn, status, etc.)")
        logger.info("     - behavior_metrics: 'behavior_search_index' (compound on domain, requestsPerMinute, etc.)")
        logger.info("  2. Create Vector Search indexes via Atlas UI:")
        logger.info("     - threat_signals: 'vs_threat_signals' (embedding field, 1024 dims, cosine)")
        logger.info("     - regional_threats: 'vs_regional' (embedding field, 1024 dims, cosine)")
        logger.info("     - visual_intelligence: 'vs_visual' (embedding field, 1024 dims, cosine)")
        logger.info("")

    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(main())
