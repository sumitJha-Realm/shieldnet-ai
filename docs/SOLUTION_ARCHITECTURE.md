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

This section explains how each collection is queried, and where embeddings are used.

### 1) urls and threat corpus
- What it stores:
	- Historical scan records and threat-intel style records.
- Search method:
	- Vector Search for semantic nearest-neighbor threat matching.
	- Search enrichment for text-driven threat-intel context.
- Embedding behavior:
	- Summary text embedding is generated for scans.
	- Reused from L2 when available for faster repeat scans.

### 2) threat_signals
- What it stores:
	- Core phishing/malware/c2/campaign threat examples.
- Search method:
	- Vector Search.
- Embedding behavior:
	- Uses threat-text embeddings to compare new URL summaries with known threat patterns.

### 3) regional_threats
- What it stores:
	- Regional-language scam patterns (Hindi, Tamil, Bengali, etc.).
- Search method:
	- Vector Search (multilingual).
- Embedding behavior:
	- Regional embedding path is used when detected language is non-English (usually from pageContent).

### 4) visual_intelligence
- What it stores:
	- Visual baseline vs impersonation-oriented descriptors.
- Search method:
	- Vector Search (conditional).
- Embedding behavior:
	- Visual-description embedding path is used only when visual/screenshot signal is available.

### 5) infrastructure_intel
- What it stores:
	- DNS, TLS, redirect-chain, hosting, fast-flux style infrastructure indicators.
- Search method:
	- Search (text + range style filtering).
- Embedding behavior:
	- No embedding required for this collection query path.

### 6) behavior_metrics
- What it stores:
	- Request-rate, error-rate, and anomaly metrics (credential stuffing/scraping/spikes).
- Search method:
	- Search (range/threshold-driven retrieval).
- Embedding behavior:
	- No embedding required for this collection query path.

### Practical summary
- Vector Search is used where semantic similarity is needed (threat_signals, regional_threats, visual_intelligence, and unified threat corpus).
- Search is used where structured text/range constraints are stronger (infrastructure_intel, behavior_metrics, and lexical enrichment).
- Embeddings are generated from scan summary text and conditionally from regional/visual context when those signals are present.

## Collections and Query Modes

| Collection | Query Mode | Purpose |
|---|---|---|
| urls and threat corpus | Vector | Similar known threats and historical scan evidence |
| threat_signals | Vector | Typosquat, phishing, malware, C2, campaign-style signals |
| regional_threats | Vector (multilingual) | Hindi, Tamil, Bengali and regional social engineering patterns |
| visual_intelligence | Vector (conditional) | Baseline vs impersonation or watering-hole style visual semantics |
| infrastructure_intel | Search | DNS, TLS anomalies, redirect chains, fast-flux and hosting indicators |
| behavior_metrics | Search | Request-rate and anomaly metrics (credential stuffing, scraping, spikes) |

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
