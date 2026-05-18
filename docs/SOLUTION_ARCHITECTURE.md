# Solution Architecture

## Overview

ShieldNet AI uses a layered detection flow that combines deterministic URL heuristics, semantic vector similarity, and Atlas lexical/range search. The runtime is optimized for fast repeat scans while still supporting deep multi-collection analysis for all 25 use cases.

## Runtime Flow (Current Logic)

### 1. Entry Points
- Single scan: POST /api/v1/scan
- Agentic scan: POST /api/v1/scan/agentic
- SOC bulk scan: POST /api/v1/scan/batch and POST /api/v1/scan/batch/csv

### 2. Waterfall Execution
- L1 cache: in-memory key based on url plus page content hash.
- L2 database hit: reuses stored embedding when possible for fast re-analysis.
- L3 full pipeline: feature extraction, enrichment, embedding, multi-source retrieval, scoring, classification, and persistence.

### 3. Signal Generation
- URL features: domain age, SSL validity, suspicious TLD, URL structure, query params, brand distance, homoglyph, DGA, payload patterns.
- Context features: pageContent (optional), language detection (hi, ta, bn, te, kn, en), QR and UPI/deeplink parsing.
- Traffic and infra flags: used to decide whether infrastructure and behavior collections are queried.

### 4. Retrieval Strategy
- Primary vector search on urls/threat corpus for similar threats.
- Multi-collection fan-out:
	- Vector: threat_signals, regional_threats, visual_intelligence.
	- Search: infrastructure_intel, behavior_metrics.
- Search enrichment over threat intel terms for extra evidence weighting.

### 5. Classification and Enforcement
- Risk score combines heuristics, vector similarity, Atlas signals, and intel counts.
- Threat class is refined by phishing-evidence rules (shorteners, UPI/QR hints, regional-language intel, brand plus phishing keywords).
- Status is assigned by thresholds (blocked, under_review, allowed), with canonical-domain status preservation when applicable.

## High-Level URL Scanning Overview (Step by Step)

This section explains the full URL scan flow in plain sequence.

1. Request intake
- Client sends URL (and optional pageContent) to /api/v1/scan.

2. Waterfall lookup
- System checks L1 cache first.
- If not found, system checks L2 database for exact URL and reusable embedding.
- If still not resolved, system runs full L3 pipeline.

3. URL feature extraction
- Domain, path, query, TLD, SSL posture, age-like signals, structural patterns, and payload indicators are extracted.
- DGA and homoglyph/brand impersonation indicators are computed.

4. Context enrichment
- If pageContent is provided, language and phishing cues are extracted.
- UPI/deeplink and QR-like signals are derived from URL/query context.

5. Summary build for retrieval/scoring
- A normalized summary text is generated from URL + extracted signals.
- Optional pageContent snippet is appended for multilingual and contextual similarity.

6. Embedding generation
- If no reusable embedding exists, the summary text is converted to vector embedding.

7. Similarity retrieval
- Vector Search fetches semantically similar threat records.
- Search fetches infrastructure and behavior evidence when relevant signals exist.
- Search enrichment adds extra lexical matches for threat-intel context.

8. Risk scoring and class refinement
- Risk score is computed using features + retrieval evidence.
- Threat class is refined with phishing overrides (shortener, regional signals, UPI/QR, brand + keywords).

9. Status decision
- Final status is assigned by thresholds (blocked, under_review, allowed).
- Canonical-domain authority can preserve status alignment.

10. Persistence and response
- URL record is upserted with latest score, status, and evidence.
- Campaign/graph linking runs if similarity evidence exists.
- API returns full result: class, status, risk breakdown, and matched evidence.

## Collection-by-Collection Search and Embedding Logic

This section explains how each collection is queried, where embeddings are used, and which seed scripts populate them.

### 1) urls (unified threat corpus)
- What it stores:
	- Historical scan records (`docType: "scan"`) and threat-intel entries (`docType: "threat_intel"`).
- Seed script: `scripts/seed_data.py` (220 scan records + 50 intel feeds).
- Search method:
	- Vector Search (`url_vector_index`) for semantic nearest-neighbor threat matching.
	- Atlas Search (`url_search_index`) for text-driven lexical enrichment.
- Embedding:
	- Model: `voyage-4-large` (1024 dimensions) via MongoDB AI endpoint.
	- Summary text embedding generated for every scan and intel record.
	- Reused from L2 database cache when available for faster repeat scans.
	- Campaign-enriched re-embedding via `scripts/backfill_campaign_embeddings.py`.

### 2) threat_signals
- What it stores:
	- Core phishing/malware/C2/campaign/supply-chain/QR-phishing/UPI-fraud threat examples.
	- Covers UC 1,3,4,7,8,11,12,13,14,19,22,23.
- Seed script: `scripts/seed_multi_collections.py`.
- Search method:
	- Vector Search (`vs_threat_signals` index).
	- Pre-filters: `attackCategory`, `threatClassification`, `source`.
- Embedding:
	- Model: `voyage-4-large` (1024 dimensions).
	- Every document embedded on ingestion.

### 3) regional_threats
- What it stores:
	- Regional-language scam patterns (Hindi, Tamil, Bengali, Telugu, Kannada).
	- Covers UC 18, 24.
- Seed script: `scripts/seed_multi_collections.py`.
- Search method:
	- Vector Search (`vs_regional` index, multilingual).
	- Pre-filters: `language`, `region`.
- Embedding:
	- Model: `voyage-4-large` (1024 dimensions, multilingual path).
	- Embeds combined `originalText` + `translatedText` for cross-language retrieval.
	- Conditional: only queried when detected language is non-English.

### 4) visual_intelligence
- What it stores:
	- Visual baseline screenshots vs phishing-capture/watering-hole diffs.
	- Covers UC 10, 11, 21.
- Seed script: `scripts/seed_multi_collections.py`.
- Search method:
	- Vector Search (`vs_visual` index, conditional).
	- Pre-filters: `type`, `brandName`.
- Embedding:
	- Model: `voyage-multimodal-3.5` (1024 dimensions) via Voyage direct API.
	- Falls back to `voyage-4-large` text embedding when multimodal API unavailable.
	- Conditional: only queried when screenshot/visual signal is available.

### 5) infrastructure_intel
- What it stores:
	- DNS anomalies, TLS certificate metadata, redirect chains, fast-flux indicators, hosting/ASN/geo data.
	- Covers UC 2, 5, 16, 17, 22.
- Seed script: `scripts/seed_multi_collections.py`.
- Search method:
	- Atlas Search (`infra_search_index`) — compound text + range filtering.
	- Fields indexed: `domain`, `asn`, `asnName`, `hostingProvider`, `status`, `tlsIssuer`, `geoCountry`, `resolvedIps`, `redirectDomains`, `ipRotationCount24h`, `ttlSeconds`, `tlsValidDays`, `redirectChainLength`.
- Embedding:
	- None. Deterministic structured queries only.

### 6) behavior_metrics
- What it stores:
	- Request-rate, error-rate, bot indicators, and anomaly metrics.
	- Covers UC 9, 20, 25.
- Seed script: `scripts/seed_multi_collections.py`.
- Search method:
	- Atlas Search (`behavior_search_index`) — range/threshold-driven retrieval.
	- Fields indexed: `domain`, `anomalyType`, `isAnomaly`, `requestsPerMinute`, `errorRate4xx`, `errorRate5xx`, `headerEntropy`, `avgTimeBetweenRequests`, `zScoreRpm`, `zScoreErrorRate`, `uniqueIps`.
- Embedding:
	- None. Threshold-based anomaly detection only.

### 7) threat_logs
- What it stores:
	- Audit trail of threat actions (blocked, allowed, flagged) with scan metadata.
- Seed script: `scripts/seed_data.py` (500 records).
- Search method:
	- Standard MongoDB indexes on `urlId`, `timestamp`, `scanTier`, `threatClassification`.
- Embedding:
	- None. Operational audit data only.

### Practical summary
- Vector Search is used where semantic similarity is needed: `urls`, `threat_signals`, `regional_threats`, `visual_intelligence`.
- Atlas Search is used where structured text/range constraints are stronger: `infrastructure_intel`, `behavior_metrics`, and lexical enrichment on `urls`.
- Standard indexes serve operational queries: `threat_logs`.
- All vector embeddings are 1024-dimensional via Voyage AI (`voyage-4-large` or `voyage-multimodal-3.5`).
- Embedding generation requires `VOYAGE_AI_API_KEY` environment variable; records are inserted without embeddings when unavailable.

## Collections and Query Modes

| Collection | Query Mode | Embedding Model | Dimensions | Purpose |
|---|---|---|---|---|
| urls | Vector + Atlas Search | voyage-4-large | 1024 | Unified scan records and threat intel corpus |
| threat_signals | Vector | voyage-4-large | 1024 | Typosquat, phishing, malware, C2, campaign-style signals |
| regional_threats | Vector (multilingual) | voyage-4-large | 1024 | Hindi, Tamil, Bengali regional social engineering patterns |
| visual_intelligence | Vector (conditional) | voyage-multimodal-3.5 | 1024 | Baseline vs impersonation or watering-hole visual semantics |
| infrastructure_intel | Atlas Search only | — | — | DNS, TLS anomalies, redirect chains, fast-flux, hosting |
| behavior_metrics | Atlas Search only | — | — | Request-rate and anomaly metrics (credential stuffing, scraping) |
| threat_logs | Standard indexes | — | — | Audit trail of scan actions and latency metrics |

## Use Case Test Matrix (UC 1-25)

This matrix now shows only whether each use case uses Search, Vector Search, or both.

| UC | Mode |
|---|---|
| UC 1 | Vector Search |
| UC 2 | Vector Search |
| UC 3 | Search + Vector Search |
| UC 4 | Search + Vector Search |
| UC 5 | Vector Search |
| UC 6 | Vector Search |
| UC 7 | Vector Search |
| UC 8 | Vector Search |
| UC 9 | Vector Search |
| UC 10 | Vector Search |
| UC 11 | Vector Search |
| UC 12 | Vector Search |
| UC 13 | Vector Search (conditional) |
| UC 14 | Vector Search |
| UC 15 | Vector Search (conditional) |
| UC 16 | Vector Search |
| UC 17 | Vector Search (conditional) |
| UC 18 | Search + Vector Search |
| UC 19 | Search + Vector Search |
| UC 20 | Search |
| UC 21 | Search |
| UC 22 | Search |
| UC 23 | Search + Vector Search |
| UC 24 | Search + Vector Search |
| UC 25 | Search |

## Notes on Conditional Paths

- Regional vector search runs when detected language is non-English, usually from pageContent.
- Visual vector search runs only when screenshot/visual signal is available.
- Infrastructure search runs when infra-related signals are present.
- Behavior search runs when traffic-anomaly signals are present; batch scan is the primary SOC path for this workflow.

## Operational Testing Guidance

- For UC 9 to UC 12 and UC 18, include pageContent in requests to activate multilingual and context-aware logic.
- For UC 25, validate both per-URL scan and batch scan behavior to verify anomaly-focused evidence.
- Use threatClassification, status, riskBreakdown, analysisSummary reasons, and source collection matches for pass/fail validation, not classification label alone.
