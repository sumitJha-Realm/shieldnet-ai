# Data Model

## Database: `shieldnet-ai`

### Collection: `urls`

Primary collection for analyzed URLs.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `url` | string | Full URL |
| `domain` | string | Extracted domain |
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
| `embedding` | array[float] | 1024-dim Voyage AI vector |
| `queryParams` | object | Parsed URL query parameters (structured key→value[]) |
| `payloadTypes` | array[string] | Detected attack types: `xss`, `sqli`, `path_traversal`, `command_injection`, `open_redirect`, `ssrf`, `credential_harvest`, `malware_download`, `base64_payload`, `obfuscated_path` |
| `redirectChain` | object | Redirect hop chain: total hops, final URL, domain change, shortener detection |
| `tlsCertificate` | object | TLS cert metadata: issuer, type (EV/OV/DV/free/self-signed), age, domain match |
| `whoisData` | object | WHOIS: registrar, privacy flag, registration country, age, expiry |
| `scanCount` | int | Number of times this URL has been submitted for scanning |
| `firstSeenAt` | ISODate | When the URL was first observed |
| `lastSeenAt` | ISODate | When the URL was most recently scanned |
| `relatedDomains` | array[string] | Domains sharing IP, ASN, or registrant with this URL's domain |
| `createdAt` | ISODate | Record creation |
| `updatedAt` | ISODate | Last update |

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

### Collection: `threat_intel_feeds`

External threat intelligence data.

| Field | Type | Description |
|-------|------|-------------|
| `_id` | ObjectId | Auto-generated |
| `feedName` | string | Source feed name |
| `url` | string | Reported URL |
| `reportedDate` | ISODate | When reported |
| `threatType` | string | `phishing`, `malware`, `c2` |
| `description` | string | Threat description |
| `embedding` | array[float] | 1024-dim vector |
| `attackCategory` | string | Granular attack type: `xss`, `sqli`, `path_traversal`, `command_injection`, `open_redirect`, `ssrf`, `obfuscated_path`, `base64_payload`, `credential_harvest`, `malware_download`, `typosquat_subdomain` |
| `targetDomain` | string | Legitimate domain being abused (e.g., `nic.in`) |
| `payloadSignature` | string | Normalised attack pattern identifier |
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `confidence` | float | Feed-level confidence (0-1) |
| `lastVerifiedAt` | ISODate | When this threat was last confirmed active |
| `iocType` | string | Indicator of Compromise type: `url`, `domain`, `ip`, `hash` |
| `ttl` | int | Time-to-live in days before auto-expiry |

## Indexes

### MongoDB Standard Indexes
- `urls.url`
- `urls.domain`
- `urls.threatClassification`
- `urls.status`
- `urls.createdAt`
- `urls.riskScore`
- `urls.payloadTypes`
- `urls.lastSeenAt`
- `urls.scanCount`
- `threat_logs.urlId`
- `threat_logs.timestamp`
- `threat_logs.scanTier`
- `threat_logs.threatClassification`
- `threat_intel_feeds.attackCategory`
- `threat_intel_feeds.targetDomain`
- `threat_intel_feeds.severity`
- `threat_intel_feeds.lastVerifiedAt`

### Atlas Search Index (`url_search_index`)
Text search on `url`, `domain`, `summaryText`, `payloadTypes` with facets on classification, DNS status, and status.

### Vector Search Index (`url_vector_index`)
Cosine similarity on `embedding` field (1024 dimensions) with pre-filters on `threatClassification` and `status`.
