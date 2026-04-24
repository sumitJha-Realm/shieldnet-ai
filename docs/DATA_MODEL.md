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

## Indexes

### MongoDB Standard Indexes
- `urls.url`
- `urls.domain`
- `urls.threatClassification`
- `urls.status`
- `urls.createdAt`
- `urls.riskScore`
- `threat_logs.urlId`
- `threat_logs.timestamp`

### Atlas Search Index (`url_search_index`)
Text search on `url`, `domain`, `summaryText` with facets on classification, DNS status, and status.

### Vector Search Index (`url_vector_index`)
Cosine similarity on `embedding` field (1024 dimensions) with pre-filters on `threatClassification` and `status`.
