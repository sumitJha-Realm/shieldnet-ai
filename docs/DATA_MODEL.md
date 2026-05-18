# Data Model

## Database: `shieldnet-ai`

## Data Flow

```
URL Scan Request
     │
     ▼
┌─────────────────┐
│  L1 In-Memory   │──hit──▶ Return cached result
│     Cache        │
└────────┬────────┘
         │ miss
         ▼
┌─────────────────┐
│  L2 Database    │──hit──▶ Reuse stored embedding + re-score
│  (urls coll)    │
└────────┬────────┘
         │ miss
         ▼
┌─────────────────────────────────────────────┐
│  L3 Full Pipeline                            │
│                                              │
│  1. Feature extraction (domain, TLD, SSL,   │
│     DGA, homoglyph, payload, structure)      │
│  2. Context enrichment (pageContent,         │
│     language detection, QR/UPI parsing)      │
│  3. Summary text build                       │
│  4. Embedding generation (voyage-4-large)    │
│  5. Multi-collection retrieval (fan-out):    │
│     ┌────────────────────────────────────┐   │
│     │ Vector Search:                     │   │
│     │  • urls (unified corpus)           │   │
│     │  • threat_signals                  │   │
│     │  • regional_threats (if non-EN)    │   │
│     │  • visual_intelligence (if visual) │   │
│     ├────────────────────────────────────┤   │
│     │ Atlas Search:                      │   │
│     │  • infrastructure_intel (if infra) │   │
│     │  • behavior_metrics (if anomaly)   │   │
│     │  • urls (lexical enrichment)       │   │
│     └────────────────────────────────────┘   │
│  6. Risk scoring + classification            │
│  7. Status decision (blocked/review/allowed) │
│  8. Persist to urls + campaign linking       │
└─────────────────────────────────────────────┘
```

---

### Collection: `urls`

Primary collection for scanned URLs and threat intelligence. Supports both Vector Search and Atlas Search.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `url` | string | Full URL |
| `domain` | string | Extracted domain |
| `docType` | string | `scan` or `threat_intel` |
| `submissionDate` | ISODate | When submitted |
| `source` | string | `gov_employee_report`, `automated_crawler`, `threat_feed` |
| `dnsStatus` | string | `active`, `inactive`, `suspended`, `parked` |
| `hostingFlags` | object | SSL, hosting provider, geo, domain age |
| `urlStructure` | object | Path depth, entropy, TLD analysis |
| `threatClassification` | string | `phishing`, `malware`, `c2`, `benign`, `suspicious` |
| `riskScore` | float | 0-100 weighted risk score |
| `status` | string | `blocked`, `allowed`, `under_review` |
| `reviewedBy` | string | `system_ai` or analyst name |
| `summaryText` | string | Natural language analysis summary |
| `embedding` | array[float] | 1024-dim Voyage AI vector (`voyage-4-large`) |
| `queryParams` | object | Parsed URL query parameters (structured key→value[]) |
| `payloadTypes` | array[string] | Detected attack types: `xss`, `sqli`, `path_traversal`, `command_injection`, `open_redirect`, `ssrf`, `credential_harvest`, `malware_download`, `base64_payload`, `obfuscated_path` |
| `redirectChain` | object | Redirect hop chain: total hops, final URL, domain change, shortener detection |
| `tlsCertificate` | object | TLS cert metadata: issuer, type (EV/OV/DV/free/self-signed), age, domain match |
| `whoisData` | object | WHOIS: registrar, privacy flag, registration country, age, expiry |
| `scanCount` | int | Number of times this URL has been submitted for scanning |
| `firstSeenAt` | ISODate | When the URL was first observed |
| `lastSeenAt` | ISODate | When the URL was most recently scanned |
| `relatedDomains` | array[string] | Domains sharing IP, ASN, or registrant with this URL's domain |
| `campaignId` | string | Campaign cluster identifier (if detected) |
| `createdAt` | ISODate | Record creation |
| `updatedAt` | ISODate | Last update |

### Collection: `threat_signals`

Core threat pattern library for vector similarity matching. Covers UC 1,3,4,7,8,11,12,13,14,19,22,23.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `url` | string | Example threat URL |
| `domain` | string | Extracted domain |
| `docType` | string | Always `threat_signal` |
| `attackCategory` | string | `typosquatting`, `credential_harvesting`, `malware_distribution`, `c2_beacon`, `qr_phishing`, `upi_fraud`, `supply_chain`, etc. |
| `threatClassification` | string | `phishing`, `malware`, `c2` |
| `summaryText` | string | Threat description for embedding |
| `embedding` | array[float] | 1024-dim vector (`voyage-4-large`) |
| `source` | string | `scanner`, `threat_feed`, `dark_web_monitor` |
| `riskScore` | float | 0-100 |
| `relatedDomains` | array[string] | Associated domains |
| `indicators` | object | Attack-specific indicators |
| `feedMetadata` | object | Source feed details (if from external feed) |
| `qrMetadata` | object | QR code analysis (if QR phishing) |
| `campaignId` | string | Campaign cluster ID |
| `discoveredAt` | ISODate | When threat was discovered |
| `createdAt` | ISODate | Record creation |

### Collection: `infrastructure_intel`

DNS, TLS, and hosting infrastructure intelligence. Atlas Search only (no embeddings). Covers UC 2,5,16,17,22.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `domain` | string | Domain name |
| `ip` | string | Resolved IP address |
| `asn` | string | AS number |
| `asnName` | string | AS organization name |
| `hostingProvider` | string | Hosting provider |
| `status` | string | `active`, `fast-flux`, `dns-tunneling`, `recently-reactivated`, `bulletproof`, `inactive` |
| `ipRotationCount24h` | int | IP changes in 24h (fast-flux indicator) |
| `ttlSeconds` | int | DNS TTL |
| `nsServers` | array[string] | Nameservers |
| `mxRecords` | array[string] | MX records |
| `resolvedIps` | array[string] | All resolved IPs |
| `tlsIssuer` | string | TLS certificate issuer |
| `tlsValidDays` | int | Days until cert expiry |
| `tlsSanMismatch` | bool | SAN doesn't match domain |
| `tlsSelfSigned` | bool | Self-signed certificate |
| `redirectChainLength` | int | Number of redirect hops |
| `redirectDomains` | array[string] | Domains in redirect chain |
| `cdnProvider` | string | CDN provider (if any) |
| `servesScripts` | bool | Serves JavaScript (supply chain risk) |
| `geoCountry` | string | Hosting country |
| `firstSeenAt` | ISODate | First observed |
| `lastSeenAt` | ISODate | Last observed |
| `createdAt` | ISODate | Record creation |

### Collection: `regional_threats`

Multilingual threat patterns for regional scam detection. Covers UC 18, 24.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `url` | string | Scam URL |
| `domain` | string | Domain |
| `language` | string | ISO 639-1 code (`hi`, `ta`, `bn`, `te`, `kn`) |
| `originalText` | string | Original regional-language text |
| `translatedText` | string | English translation |
| `summaryText` | string | Combined text for embedding |
| `embedding` | array[float] | 1024-dim vector (`voyage-4-large` multilingual) |
| `attackCategory` | string | Attack type |
| `targetBrand` | string | Impersonated brand |
| `region` | string | Geographic region |
| `riskScore` | float | 0-100 |
| `source` | string | `regional_monitor` |
| `createdAt` | ISODate | Record creation |

### Collection: `visual_intelligence`

Visual/screenshot comparison for brand impersonation detection. Covers UC 10, 11, 21.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `url` | string | URL of captured page |
| `domain` | string | Domain |
| `type` | string | `baseline`, `phishing_capture`, `watering_hole_diff` |
| `brandName` | string | Brand being compared |
| `screenshotHash` | string | Screenshot perceptual hash |
| `description` | string | Visual description text |
| `embedding` | array[float] | 1024-dim vector (`voyage-multimodal-3.5`) |
| `similarityToBaseline` | float | Visual similarity score |
| `capturedAt` | ISODate | When screenshot was taken |
| `createdAt` | ISODate | Record creation |

### Collection: `behavior_metrics`

Traffic anomaly and bot detection metrics. Atlas Search only (no embeddings). Covers UC 9, 20, 25.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `domain` | string | Domain |
| `url` | string | Specific URL (optional) |
| `requestsPerMinute` | float | Request rate |
| `uniqueIps` | int | Unique source IPs |
| `avgResponseTimeMs` | float | Average response time |
| `errorRate4xx` | float | 4xx error rate |
| `errorRate5xx` | float | 5xx error rate |
| `headerEntropy` | float | HTTP header entropy (bot indicator) |
| `avgTimeBetweenRequests` | float | Mean inter-request interval (ms) |
| `userAgentVariety` | int | Distinct User-Agents |
| `hasCaptchaBypass` | bool | Captcha bypass detected |
| `isAnomaly` | bool | Anomaly flag |
| `anomalyType` | string | `traffic_spike`, `bot_swarm`, `credential_stuffing` |
| `zScoreRpm` | float | Z-score for request rate |
| `zScoreErrorRate` | float | Z-score for error rate |
| `windowStart` | ISODate | Metric window start |
| `windowEnd` | ISODate | Metric window end |
| `createdAt` | ISODate | Record creation |

### Collection: `threat_logs`

Audit trail of threat actions.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `urlId` | ObjectId | Reference to `urls._id` |
| `timestamp` | ISODate | Action time |
| `action` | string | `blocked`, `allowed`, `flagged` |
| `userDepartment` | string | Government department |
| `userType` | string | `gov_employee` |
| `deviceType` | string | `desktop`, `mobile` |
| `ipRegion` | string | Region identifier |
| `aiConfidence` | float | AI confidence score (0-1) |
| `riskScore` | float | Risk score at time of action (0-100) |
| `threatClassification` | string | Classification at time of action |
| `triggerReasons` | array[string] | Detection modules that triggered: `dga`, `homoglyph`, `vector_match`, etc. |
| `scanTier` | string | Waterfall tier: `L1_CACHE`, `L2_DATABASE`, `L3_FULL_PIPELINE` |
| `responseTimeMs` | float | End-to-end scan latency in milliseconds |

---

## Indexes

### Atlas Vector Search Indexes

| Index Name | Collection | Dimensions | Similarity | Pre-filters |
|---|---|---|---|---|
| `url_vector_index` | urls | 1024 | cosine | `threatClassification`, `status` |
| `vs_threat_signals` | threat_signals | 1024 | cosine | `attackCategory`, `threatClassification`, `source` |
| `vs_regional` | regional_threats | 1024 | cosine | `language`, `region` |
| `vs_visual` | visual_intelligence | 1024 | cosine | `type`, `brandName` |

### Atlas Search Indexes

| Index Name | Collection | Key Fields |
|---|---|---|
| `url_search_index` | urls | `url`, `domain`, `summaryText`, `payloadTypes` + facets on classification/status |
| `infra_search_index` | infrastructure_intel | `domain`, `asn`, `asnName`, `hostingProvider`, `status`, `tlsIssuer`, `geoCountry`, `resolvedIps`, `redirectDomains`, `ipRotationCount24h`, `ttlSeconds`, `tlsValidDays`, `redirectChainLength` |
| `behavior_search_index` | behavior_metrics | `domain`, `anomalyType`, `isAnomaly`, `requestsPerMinute`, `errorRate4xx`, `errorRate5xx`, `headerEntropy`, `avgTimeBetweenRequests`, `zScoreRpm`, `zScoreErrorRate`, `uniqueIps` |

### MongoDB Standard Indexes
- `urls`: `url`, `domain`, `threatClassification`, `status`, `createdAt`, `riskScore`, `payloadTypes`, `lastSeenAt`, `scanCount`
- `threat_logs`: `urlId`, `timestamp`, `scanTier`, `threatClassification`
