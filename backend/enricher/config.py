"""Configurable brand lists, suspicious ASNs, and enrichment settings."""

from __future__ import annotations

# ── Known government brand domains for impersonation detection ────────────
# Maps domain → organisation name for narrative output.
BRAND_DOMAINS: dict[str, str] = {
    # Indian government domains
    "rbi.org.in": "Reserve Bank of India",
    "incometax.gov.in": "Income Tax Department",
    "sbi.co.in": "State Bank of India",
    "nic.in": "National Informatics Centre",
    "gov.in": "Government of India Portal",
    "uidai.gov.in": "UIDAI / Aadhaar",
    "irctc.co.in": "Indian Railway Catering & Tourism",
    "epfindia.gov.in": "Employees' Provident Fund Organisation",
    "passportindia.gov.in": "Passport Seva",
    "india.gov.in": "National Portal of India",
    "cert-in.org.in": "CERT-IN",
    "mygov.in": "MyGov India",
    "digitalindia.gov.in": "Digital India",
    "nsdl.co.in": "NSDL",
    "data.gov.in": "Open Government Data Platform",
    "digilocker.gov.in": "DigiLocker",
    "cowin.gov.in": "CoWIN Vaccination",
    "pib.gov.in": "Press Information Bureau",
    "meity.gov.in": "Ministry of Electronics & IT",
    # Global brands commonly targeted by phishing
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "facebook.com": "Facebook / Meta",
    "paypal.com": "PayPal",
    "netflix.com": "Netflix",
    "linkedin.com": "LinkedIn",
    "dropbox.com": "Dropbox",
    "outlook.com": "Microsoft Outlook",
    "instagram.com": "Instagram",
    "twitter.com": "Twitter / X",
    "whatsapp.com": "WhatsApp",
    "github.com": "GitHub",
    "zoom.us": "Zoom",
    "office.com": "Microsoft Office",
    "live.com": "Microsoft Live",
    "yahoo.com": "Yahoo",
}

# ── Suspicious ASN numbers ────────────────────────────────────────────────
# ASNs frequently associated with bulletproof hosting / abuse.
SUSPICIOUS_ASNS: set[int] = {
    # Bulletproof / abuse-heavy
    4134,    # ChinaNet
    4837,    # China Unicom
    9009,    # M247 (frequent abuse)
    16276,   # OVH (high abuse fraction)
    24940,   # Hetzner (some abuse)
    36352,   # ColoCrossing
    46664,   # VolumeDrive
    47583,   # Hostinger abuse-heavy range
    49981,   # WorldStream
    200019,  # AlexHost (Moldova — bulletproof reputation)
    62567,   # DigitalOcean abuse segment
    394711,  # Limenet
}

# ── Known URL shorteners ─────────────────────────────────────────────────
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly",
    "ow.ly", "buff.ly", "adf.ly", "bl.ink", "soo.gd", "s.id",
    "rb.gy", "cutt.ly", "shorturl.at",
}

# ── Suspicious keywords in URL path/params ────────────────────────────────
SUSPICIOUS_KEYWORDS: set[str] = {
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "signin", "credential", "auth", "validate",
    "suspend", "unlock", "reactivate", "alert", "notification", "otp",
    "transfer", "kyc", "beneficiary",
}

# ── Cloud / CDN provider ASN patterns ─────────────────────────────────────
CLOUD_ASNS: dict[str, str] = {
    "AS16509": "AWS",
    "AS14618": "AWS",
    "AS15169": "Google Cloud",
    "AS396982": "Google Cloud",
    "AS8075": "Microsoft Azure",
    "AS13335": "Cloudflare",
    "AS20940": "Akamai",
    "AS54113": "Fastly",
    "AS14061": "DigitalOcean",
    "AS63949": "Linode / Akamai",
    "AS24940": "Hetzner",
    "AS16276": "OVH",
    "AS132203": "Tencent Cloud",
    "AS45102": "Alibaba Cloud",
}

# ── Timeouts (seconds) ───────────────────────────────────────────────────
DNS_TIMEOUT: float = 2.0
WHOIS_TIMEOUT: float = 3.0
TLS_TIMEOUT: float = 2.0
HTTP_TIMEOUT: float = 3.0
GEOIP_TIMEOUT: float = 2.0

# ── Cache TTLs (seconds) ─────────────────────────────────────────────────
CACHE_TTL_WHOIS: int = 86_400       # 24 hours
CACHE_TTL_GEOIP: int = 604_800      # 7 days
CACHE_TTL_DNS_DEFAULT: int = 300     # 5 min fallback when TTL not in response

# ── Redirect limits ──────────────────────────────────────────────────────
MAX_REDIRECTS: int = 10
