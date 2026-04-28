# URL Scanning Scenarios - Example URLs & Explanations

This guide provides example URLs for demonstrating all threat detection scenarios in the ShieldNet AI scanner.

---

## 1. BENIGN URLs (Status: Allowed, Risk: Low)

Safe, legitimate websites with no threat indicators.

| URL | Why It's Benign | Risk Score | Status |
|-----|-----------------|-----------|--------|
| `google.com` | Legitimate search engine, trusted brand | 0-5 | Allowed |
| `github.com` | Legitimate code repository platform | 0-5 | Allowed |
| `stackoverflow.com` | Legitimate developer Q&A platform | 0-5 | Allowed |
| `microsoft.com` | Legitimate enterprise software company | 0-5 | Allowed |
| `wikipedia.org` | Legitimate encyclopedia, trusted content | 0-5 | Allowed |
| `www.amazon.com` | Legitimate e-commerce platform | 0-5 | Allowed |
| `apple.com` | Legitimate technology company | 0-5 | Allowed |

**What Scanner Detects:**
- ✅ Valid SSL certificate
- ✅ Established domain age
- ✅ No malware signatures
- ✅ No phishing patterns
- ✅ No DGA characteristics
- ✅ Legitimate Alexa ranking

---

## 2. PHISHING URLs (Status: Blocked, Risk: High)

Attempts to steal credentials/data by impersonating legitimate services.

### 2.1 Homoglyph/Typosquatting (Homoglyph-based)

| URL | Trick Used | Why It's Phishing | Risk Score | Status |
|-----|-----------|------------------|-----------|--------|
| `g00gle.com` | Zero (0) replaces O | Looks like Google | 72-85 | Blocked |
| `am4zon.com` | 4 replaces A | Looks like Amazon | 70-82 | Blocked |
| `appl3.com` | 3 replaces E | Looks like Apple | 68-80 | Blocked |
| `1bm.com` | l (lowercase L) replaces I, 1 (one) at start | Looks like IBM | 65-78 | Blocked |
| `vv1ndows.com` | v + lowercase L replace w | Looks like Windows | 70-83 | Blocked |

**What Scanner Detects:**
- 🔴 Confusable character substitution (homoglyphs)
- 🔴 Resembles legitimate brand
- 🔴 Phishing keywords in domain
- 🔴 Brand impersonation patterns

**Scanner Output Example:**
```json
{
  "threatClassification": "phishing",
  "status": "blocked",
  "riskScore": 78.5,
  "reasons": [
    "Homoglyph impersonation: 'g00gle.com' resembles 'google.com'",
    "Uses confusable characters (zero as O)",
    "Registered domain mimics well-known brand"
  ],
  "riskBreakdown": {
    "hasHomoglyphs": true,
    "phishingKeywords": ["google"],
    "brandImpersonation": true
  }
}
```

---

### 2.2 Fake Security/Account Alert Phishing

| URL | Social Engineering Tactic | Risk Score | Status |
|-----|---------------------------|-----------|--------|
| `secure-paypal-confirm.com` | Fake security confirmation page | 75-88 | Blocked |
| `apple-id-verify.net` | Fake Apple ID verification | 74-87 | Blocked |
| `amazon-account-update.info` | Fake account update notice | 73-86 | Blocked |
| `microsoft-security-alert.xyz` | Fake Windows security alert | 76-89 | Blocked |
| `fb-login-verify.tk` | Fake Facebook login verification | 72-85 | Blocked |

**What Scanner Detects:**
- 🔴 Phishing keywords: "verify", "confirm", "security", "alert", "update"
- 🔴 Brand name + legitimate service combination
- 🔴 Suspicious TLDs (.info, .xyz, .tk)
- 🔴 Non-standard domain construction

**Scanner Output Example:**
```json
{
  "threatClassification": "phishing",
  "status": "blocked",
  "riskScore": 81.3,
  "reasons": [
    "Phishing keywords detected: 'secure', 'paypal', 'confirm'",
    "Social engineering pattern: Account verification lure",
    "Suspicious domain structure for brand impersonation"
  ],
  "riskBreakdown": {
    "phishingKeywords": ["secure", "paypal", "confirm", "verify"],
    "socialEngineeringScore": 8.2,
    "brandImpersonation": true
  }
}
```

---

### 2.3 Lookalike/Misspelling Phishing

| URL | Misspelling Type | Looks Like | Risk Score | Status |
|-----|------------------|-----------|-----------|--------|
| `goog1e.com` | Letter/number confusion | Google | 68-80 | Blocked |
| `paipal.com` | Missing letter (a→a replaced with p) | PayPal | 70-83 | Blocked |
| `linkedln.com` | Character substitution (i→l) | LinkedIn | 69-81 | Blocked |
| `gitbub.com` | Typo (h→u) | GitHub | 65-78 | Blocked |
| `twiter.com` | Missing letter | Twitter | 64-77 | Blocked |

**What Scanner Detects:**
- 🔴 Levenshtein distance < 3 from legitimate domain
- 🔴 Brand reputation mismatch
- 🔴 Structural similarity to known brands

---

## 3. MALWARE URLs (Status: Blocked, Risk: Critical)

Distribute malicious software (trojans, ransomware, spyware, etc.).

| URL | Malware Type | Infection Vector | Risk Score | Status |
|-----|--------------|-----------------|-----------|--------|
| `malware-distribution-site.net` | Trojan/Worm hosting | Executable download | 85-95 | Blocked |
| `ransomware-c2-server.xyz` | Ransomware C2 communication | File encryption malware | 92-98 | Blocked |
| `exploit-kit-payload.tk` | Exploit kit hosting | Browser vulnerability | 88-96 | Blocked |
| `botnet-command-center.ru` | Botnet command server | Bot malware | 90-97 | Blocked |
| `suspicious-executable-download.info` | Malware dropper | Software trojan | 84-94 | Blocked |
| `worm-distribution.net` | Worm hosting | Network worm | 86-95 | Blocked |
| `spyware-installer.xyz` | Spyware hosting | Information stealer | 83-93 | Blocked |
| `adware-pusher.tk` | Adware/PUP hosting | Unwanted software | 78-88 | Blocked |

**What Scanner Detects:**
- 🔴 Malware keywords: "malware", "trojan", "ransomware", "exploit", "botnet", "worm", "spyware", "adware"
- 🔴 Reputation data from threat feeds
- 🔴 Known malware hosting patterns
- 🔴 Suspicious hosting infrastructure (.ru, .tk, .xyz)
- 🔴 File download patterns

**Scanner Output Example:**
```json
{
  "threatClassification": "malware",
  "status": "blocked",
  "riskScore": 91.7,
  "reasons": [
    "Malware keywords in domain: 'ransomware', 'c2', 'server'",
    "Domain associated with command-and-control infrastructure",
    "High-risk hosting provider detected"
  ],
  "riskBreakdown": {
    "malwareKeywords": ["ransomware", "c2", "server"],
    "suspiciousHosting": true,
    "reputationScore": -95
  }
}
```

---

## 4. C2 (COMMAND & CONTROL) URLs (Status: Blocked, Risk: Critical)

Infrastructure used by attackers to control infected machines/botnets.

| URL | C2 Type | Botnet/APT Name | Risk Score | Status |
|-----|---------|-----------------|-----------|--------|
| `c2-botnet-panel.tk` | Botnet C2 panel | Generic botnet | 89-97 | Blocked |
| `command-control-server.ru` | C2 communication server | APT infrastructure | 91-98 | Blocked |
| `botnet-c2-communication.xyz` | Botnet command channel | Bot network | 90-97 | Blocked |
| `underground-c2-panel.net` | Underground marketplace C2 | Cybercriminal panel | 93-99 | Blocked |
| `remote-access-trojan-c2.info` | RAT C2 server | RAT malware | 92-98 | Blocked |
| `apt-command-center.ru` | APT infrastructure | Advanced persistent threat | 94-99 | Blocked |
| `ransomware-negotiation-site.net` | Ransomware negotiation/payment | Ransomware gang | 90-97 | Blocked |
| `dga-sink-domain.tk` | DGA sinkhole (legitimate security research) | Botnet DGA | 87-95 | Blocked |

**What Scanner Detects:**
- 🔴 C2 keywords: "c2", "command", "control", "botnet", "panel", "server"
- 🔴 APT/malware framework indicators
- 🔴 Registered by known threat actors
- 🔴 Hosting infrastructure in high-risk countries
- 🔴 Network behavior patterns

**Scanner Output Example:**
```json
{
  "threatClassification": "c2",
  "status": "blocked",
  "riskScore": 94.2,
  "reasons": [
    "C2 infrastructure keywords detected: 'c2', 'command', 'control'",
    "Matches known botnet panel registration patterns",
    "Infrastructure hosted in high-risk jurisdiction (RU)"
  ],
  "riskBreakdown": {
    "c2Keywords": ["c2", "command", "control"],
    "knownC2Infrastructure": true,
    "highRiskJurisdiction": true
  }
}
```

---

## 5. DGA (DOMAIN GENERATION ALGORITHM) Domains (Status: Blocked, Risk: High)

Malware-generated domains using algorithmic patterns to evade detection.

| URL | DGA Pattern | Why It's DGA | Risk Score | Status |
|-----|-------------|------------|-----------|--------|
| `xkfrzmkbpq.tk` | Random consonant clusters | High entropy, no vowels | 75-88 | Blocked |
| `ndkqmxbzpg.net` | Vowel-light, random pattern | Algorithmic generation | 73-86 | Blocked |
| `qpxdvmkrst.xyz` | All consonants, high entropy | DGA characteristic | 76-89 | Blocked |
| `bfjmkxqwpn.info` | Unusual letter combinations | Algorithm-generated | 74-87 | Blocked |

**What Scanner Detects:**
- 🔴 Entropy analysis (high randomness)
- 🔴 Unusual character distribution (too many consonants, no vowels)
- 🔴 Unpronounceable domain patterns
- 🔴 Known DGA signatures
- 🔴 Structural anomalies (length, character distribution)

**Scanner Output Example:**
```json
{
  "threatClassification": "suspicious",
  "status": "blocked",
  "riskScore": 81.4,
  "reasons": [
    "Domain shows DGA characteristics: High entropy (8.2/10)",
    "Unpronounceable letter combinations detected",
    "Pattern matches known botnet DGA algorithm (Conficker family)"
  ],
  "riskBreakdown": {
    "dgaScore": 8.2,
    "entropy": 7.9,
    "hasUnusualCharacterDistribution": true
  }
}
```

---

## 6. SUSPICIOUS URLs (Status: Flagged, Risk: Medium-High)

Questionable or potentially malicious, but insufficient evidence for definitive classification.

| URL | Suspicion Reason | Risk Score | Status |
|-----|-----------------|-----------|--------|
| `slightly-suspicious-domain.tk` | Suspicious TLD + vague naming | 58-70 | Flagged |
| `looks-like-phishing.net` | Phishing keywords, not definitively phishing | 62-74 | Flagged |
| `potential-scam-site.xyz` | Scam keywords + risky TLD | 65-77 | Flagged |
| `questionable-business.info` | Questionable purpose + suspicious TLD | 60-72 | Flagged |
| `unclear-legitimacy.tk` | Unclear purpose, risky hosting | 59-71 | Flagged |
| `possibly-malicious.net` | Malware-adjacent keywords | 64-76 | Flagged |
| `risky-download-site.xyz` | Download + suspicious pattern | 66-78 | Flagged |

**What Scanner Detects:**
- ⚠️ Suspicious TLDs (.tk, .xyz, .info)
- ⚠️ Vague or concerning naming patterns
- ⚠️ Weak SSL certificates
- ⚠️ Recent domain registration (< 30 days)
- ⚠️ No clear business purpose

**Scanner Output Example:**
```json
{
  "threatClassification": "suspicious",
  "status": "flagged",
  "riskScore": 68.5,
  "reasons": [
    "Suspicious TLD detected: .xyz",
    "Domain registered < 30 days ago",
    "Ambiguous business purpose",
    "Vague naming pattern suggests potential scam"
  ],
  "riskBreakdown": {
    "suspiciousTLD": 0.35,
    "recentRegistration": 0.25,
    "vagueNaming": 0.15,
    "unknownReputation": 0.15
  }
}
```

---

## 7. CANONICALIZATION SCENARIOS (Domain Variants)

Shows how the scanner handles apex domain vs. www variant alignment.

| URL | Canonical | Expected Status | Actual Status | Reason |
|-----|-----------|-----------------|---------------|--------|
| `google.com` | google.com | Allowed | Allowed | Legitimate brand |
| `www.google.com` | google.com | Allowed | Allowed | **Canonical-aligned:** Inherits status from apex |
| `blocked-domain.net` | blocked-domain.net | Blocked | Blocked | Malicious |
| `www.blocked-domain.net` | blocked-domain.net | Blocked | Blocked | **Canonical-aligned:** Inherits status from apex |

**What Scanner Detects:**
- ✅ Domain canonicalization (www prefix normalization)
- ✅ Status inheritance from canonical authority (apex domain)
- ✅ Risk score alignment across variants
- ✅ Single threat classification for domain family

**Scanner Output Example:**
```json
{
  "url": "www.google.com",
  "canonicalDomain": "google.com",
  "canonicalAuthorityUrl": "google.com",
  "status": "allowed",
  "riskScore": 2.1,
  "reasons": [
    "Canonical-domain alignment: Status inherited from authority (google.com)",
    "Legitimate brand - no threats detected"
  ],
  "riskBreakdown": {
    "canonicalAlignment": 0.1,
    "baseRisk": 2.0
  }
}
```

---

## 8. CAMPAIGN-COORDINATED URLS (Multi-Domain Attack)

Related URLs part of the same phishing/malware campaign.

| URL | Campaign | Campaign Name | Risk Score | Status |
|-----|----------|---------------|-----------|--------|
| `paypal-verify-account.tk` | Campaign ID: `campaign_001_paypal_2025` | PayPal Phishing Campaign | 82-89 | Blocked |
| `paypal-update-billing.xyz` | Campaign ID: `campaign_001_paypal_2025` | PayPal Phishing Campaign | 81-88 | Blocked |
| `paypal-security-alert.net` | Campaign ID: `campaign_001_paypal_2025` | PayPal Phishing Campaign | 83-90 | Blocked |
| `amazon-account-verify.tk` | Campaign ID: `campaign_002_amazon_2025` | Amazon Phishing Campaign | 80-87 | Blocked |
| `amazon-order-confirm.xyz` | Campaign ID: `campaign_002_amazon_2025` | Amazon Phishing Campaign | 79-86 | Blocked |

**What Scanner Detects:**
- 🔴 Shared characteristics (phishing keywords, similar structure)
- 🔴 Same registration infrastructure (registrar, IP)
- 🔴 Temporal clustering (registered around same time)
- 🔴 Campaign linkage via embedding similarity
- 🔴 Coordinated threat actors

**Scanner Output Example:**
```json
{
  "url": "paypal-verify-account.tk",
  "threatClassification": "phishing",
  "status": "blocked",
  "riskScore": 85.3,
  "campaign": {
    "campaignId": "campaign_001_paypal_2025",
    "campaignName": "PayPal Phishing Campaign Q1 2025",
    "relatedUrls": [
      "paypal-update-billing.xyz",
      "paypal-security-alert.net"
    ],
    "knownRegistrant": "threat_actor_group_05"
  },
  "reasons": [
    "Part of coordinated phishing campaign targeting PayPal users",
    "3 related domains registered in same infrastructure",
    "Matches campaign 001 embedding signature"
  ]
}
```

---

## 9. CATEGORICAL EXPLANATIONS

### Risk Score Ranges

| Risk Score | Status | Color | Example URLs |
|-----------|--------|-------|--------------|
| 0-20 | **Allowed** | 🟢 Green | google.com, github.com, wikipedia.org |
| 21-40 | **Low Risk** | 🟡 Yellow | Newer businesses, low-confidence threats |
| 41-60 | **Medium Risk** | 🟠 Orange | slightly-suspicious-domain.tk |
| 61-75 | **High Risk** | 🔴 Red | looks-like-phishing.net, potential-scam.xyz |
| 76-100 | **Critical** | ⛔ Blocked | g00gle.com, malware-distribution.net, c2-server.ru |

### Status Indicators

| Status | Meaning | Action | Example |
|--------|---------|--------|---------|
| **Allowed** | Safe, no threats | Visit freely | google.com |
| **Flagged** | Suspicious, caution | Investigate further | slightly-suspicious-domain.tk |
| **Blocked** | Malicious, dangerous | Prevent access | g00gle.com, malware-site.net |

---

## 10. DEMO FLOW: STEP-BY-STEP WALKTHROUGH

### Step 1: Show Benign URL
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "google.com"}'
```
**Expected Result:** Status: "allowed", Risk: 2-5, No threats

---

### Step 2: Show Phishing URL (Homoglyph)
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "g00gle.com"}'
```
**Expected Result:** Status: "blocked", Risk: 78-85, "Homoglyph impersonation detected"

---

### Step 3: Show Malware URL
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "malware-distribution-site.net"}'
```
**Expected Result:** Status: "blocked", Risk: 85-95, "Malware keywords detected"

---

### Step 4: Show DGA Domain
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "xkfrzmkbpq.tk"}'
```
**Expected Result:** Status: "blocked", Risk: 75-88, "DGA characteristics detected"

---

### Step 5: Show Canonical Alignment
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "www.google.com"}'
```
**Expected Result:** Same as google.com, Status: "allowed", Risk: 2-5, "Canonical-domain aligned"

---

### Step 6: Show Campaign-Related URLs
```bash
# First URL
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "paypal-verify-account.tk"}'

# Related URL (should show campaign link)
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "paypal-update-billing.xyz"}'
```
**Expected Result:** Same campaign ID, Related URLs listed

---

## 11. QUICK REFERENCE TABLE

Best URLs to demonstrate each feature:

| Feature | Best URL | What It Shows |
|---------|----------|--------------|
| **Benign Detection** | `google.com` | Clean scan, no threats |
| **Homoglyph Phishing** | `g00gle.com` | Character substitution attack |
| **Fake Alert Phishing** | `secure-paypal-confirm.com` | Social engineering |
| **Typosquatting** | `goog1e.com` | Misspelling attack |
| **Malware Hosting** | `malware-distribution-site.net` | Malicious software distribution |
| **C2 Infrastructure** | `c2-botnet-panel.tk` | Bot command center |
| **DGA Detection** | `xkfrzmkbpq.tk` | Algorithm-generated randomness |
| **Suspicious Domain** | `slightly-suspicious-domain.tk` | Medium-risk indicators |
| **Canonical Alignment** | `www.google.com` | Domain variant normalization |
| **Campaign Clustering** | `paypal-verify-account.tk` | Coordinated attack |

---

## 12. NARRATIVE EXPLANATIONS FOR DEMO

### Scenario A: User navigates to a typosquatted site
**User:** "I clicked on what I thought was google.com but it was spelled slightly differently"

**Demo:**
1. Scan: `goog1e.com` → Risk: 75, Status: Blocked, "Typosquatting detected"
2. Explain: "The scanner caught the misspelling (i instead of L) and blocked it before you could enter credentials"
3. Compare: Scan `google.com` → Risk: 2, Status: Allowed, "This is legitimate"

---

### Scenario B: Ransomware delivery prevention
**User:** "I received an email with a download link that seemed suspicious"

**Demo:**
1. Scan: `malware-distribution-site.net` → Risk: 92, Status: Blocked, "Malware keywords detected"
2. Explain: "The domain name itself contains 'malware' which is flagged. The scanner also checks threat reputation databases and would block delivery"
3. Risk Breakdown: "Malware keywords (35%), Suspicious hosting (40%), Reputation score (-95)"

---

### Scenario C: Botnet C2 communication prevention
**User:** "How does the scanner detect command-and-control infrastructure?"

**Demo:**
1. Scan: `c2-botnet-panel.tk` → Risk: 94, Status: Blocked, "C2 infrastructure detected"
2. Explain: "The scanner recognizes 'C2', 'botnet', 'panel' keywords and identifies high-risk TLD (.tk). It correlates with known APT infrastructure patterns"
3. Impact: "This blocks your machine from being controlled by attackers even if malware gets installed"

---

### Scenario D: Phishing campaign tracking
**User:** "How does the scanner handle coordinated attacks?"

**Demo:**
1. Scan: `paypal-verify-account.tk` → Campaign: `campaign_001_paypal_2025`, Related: 2 URLs
2. Scan: `paypal-update-billing.xyz` → Same campaign detected
3. Explain: "The scanner clusters related domains into campaigns using shared patterns (keywords, registration infrastructure, embeddings). This helps identify coordinated threat actors"

---

## Usage Tips

1. **For Security Teams:** Use the Campaign IDs to block all related domains at once
2. **For End Users:** Use the Risk Score and Status to understand threat severity
3. **For Analysts:** Use the Risk Breakdown to understand which factors contributed to the score
4. **For Training:** Use Scenario A-D narratives to explain real-world threats

---

