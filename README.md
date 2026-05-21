# ShieldNet AI — Real-Time Malicious URL Detection Platform

A full-stack security platform for **NIC (National Informatics Centre)** that uses Semantic AI to identify and block malicious URLs. Built with Next.js 15, FastAPI, MongoDB Atlas Search + Vector Search, and Voyage AI embeddings.

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│   Next.js 15    │────▶│   FastAPI Backend     │────▶│  MongoDB Atlas   │
│   Frontend      │     │   (Python)            │     │  - Atlas Search  │
│   LeafyGreen UI │◀────│   Motor (async)       │◀────│  - Vector Search │
│   Recharts      │     │   Pydantic            │     │  - $rankFusion   │
└─────────────────┘     └──────────┬───────────┘     └──────────────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   Voyage AI API      │
                        │   voyage-3 (1024d)   │
                        └──────────────────────┘
```

---

## Setup Guide

### Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ | Required for backend |
| Node.js | 20+ | Required for frontend |
| Poetry | Latest | Install via `pip install poetry` |
| MongoDB Atlas | M0 (free) or higher | Must have **Search** enabled on the cluster |
| Voyage AI API Key | — | Get from [voyageai.com](https://dash.voyageai.com/) |
| Microsoft Foundry API Key | — | *(Optional)* Required only for agentic scan mode |

---

### Step 1: Clone the Repository

```bash
git clone https://github.com/<your-org>/shieldnet-ai.git
cd shieldnet-ai
```

---

### Step 2: Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and fill in **your** values:

```env
# Required
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
VOYAGE_AI_API_KEY=<your-voyage-ai-api-key>

# Optional — for Foundry-powered agentic scan mode
GROVE_FOUNDRY_CHAT_URL=https://grove-gateway-prod.azure-api.net/grove-foundry-prod/openai/v1/chat/completions
GROVE_API_KEY=<your-foundry-api-key>
GROVE_FOUNDRY_MODEL=gpt-5.4
```

> **Note:** The `MONGODB_URI` must point to a MongoDB Atlas cluster (not a local MongoDB). Atlas Search and Vector Search features require Atlas.

---

### Step 3: Install Backend Dependencies

```bash
cd backend
poetry install
```

This installs FastAPI, Motor, Pydantic, httpx, dnspython, and all other backend dependencies.

---

### Step 4: Seed the Database

Run **all three** seed scripts in order to populate all 10 collections:

```bash
cd backend

# Step 4a: Core collections (urls, threat_logs)
poetry run python -m scripts.seed_data

# Step 4b: Multi-collection threat data (threat_signals, infrastructure_intel, regional_threats, visual_intelligence, behavior_metrics)
poetry run python -m scripts.seed_multi_collections

# Step 4c: Scan rule reference examples (scan_rules)
poetry run python -m scripts.seed_rule_examples
```

This populates your MongoDB Atlas database (`shieldnet-ai`) with all **10 collections**:

| Collection | Records | Seed Script | Description |
|---|---|---|---|
| `urls` | 220+ | `seed_data` | Malicious & benign URL records with risk scores + threat intel feeds |
| `threat_logs` | 500+ | `seed_data` | Historical threat detection logs |
| `threat_signals` | 20+ | `seed_multi_collections` | Attack signals with voyage-3-large embeddings |
| `infrastructure_intel` | 7+ | `seed_multi_collections` | DNS, TLS, hosting infrastructure data (Atlas Search) |
| `regional_threats` | 7+ | `seed_multi_collections` | Multilingual threats (Hindi/Tamil/Bengali) with voyage-multilingual-2 embeddings |
| `visual_intelligence` | 6+ | `seed_multi_collections` | Brand impersonation visual data with voyage-multimodal-3 embeddings |
| `behavior_metrics` | 5+ | `seed_multi_collections` | Bot detection & traffic anomaly metrics (Atlas Search) |
| `scan_rules` | 15+ | `seed_rule_examples` | Detection rule reference documents for vector similarity |
| `campaigns` | — | Auto-generated | Detected coordinated attack campaigns (created at runtime) |
| `url_edges` | — | Auto-generated | URL relationship graph edges (created at runtime) |

If `VOYAGE_AI_API_KEY` is set in `.env`, the seed scripts will also generate **vector embeddings** using the appropriate Voyage AI model for each collection. These embeddings power Vector Search and Hybrid Search.

> **Tip:** If you skip the API key, seeding still works — but Vector Search won't return results until embeddings are generated.

---

### Step 5: Create Atlas Search Indexes

In the **MongoDB Atlas UI**, navigate to your cluster → **Atlas Search** → **Create Index**.

#### 5a. `urls` — Atlas Search Index

- **Index Name:** `url_search_index`
- **Collection:** `urls`
- **Configuration:**

```json
{
  "mappings": {
    "dynamic": false,
    "fields": {
      "url": { "type": "string", "analyzer": "lucene.standard" },
      "domain": { "type": "string", "analyzer": "lucene.keyword" },
      "summaryText": { "type": "string", "analyzer": "lucene.standard" },
      "threatClassification": { "type": "stringFacet" },
      "dnsStatus": { "type": "stringFacet" },
      "status": { "type": "stringFacet" },
      "riskScore": { "type": "number" },
      "submissionDate": { "type": "date" }
    }
  }
}
```

#### 5b. `urls` — Vector Search Index

- **Index Name:** `url_vector_index`
- **Collection:** `urls`
- **Type:** Vector Search
- **Configuration:**

```json
{
  "fields": [
    { "type": "vector", "path": "embedding", "numDimensions": 1024, "similarity": "cosine" },
    { "type": "filter", "path": "threatClassification" },
    { "type": "filter", "path": "status" }
  ]
}
```

#### 5c. `threat_signals` — Vector Search Index

- **Index Name:** `vs_threat_signals`
- **Collection:** `threat_signals`
- **Type:** Vector Search
- **Configuration:**

```json
{
  "fields": [
    { "type": "vector", "path": "embedding", "numDimensions": 1024, "similarity": "cosine" },
    { "type": "filter", "path": "attackCategory" },
    { "type": "filter", "path": "threatClassification" }
  ]
}
```

#### 5d. `regional_threats` — Vector Search Index

- **Index Name:** `vs_regional`
- **Collection:** `regional_threats`
- **Type:** Vector Search
- **Configuration:**

```json
{
  "fields": [
    { "type": "vector", "path": "embedding", "numDimensions": 1024, "similarity": "cosine" },
    { "type": "filter", "path": "language" },
    { "type": "filter", "path": "region" }
  ]
}
```

#### 5e. `visual_intelligence` — Vector Search Index

- **Index Name:** `vs_visual`
- **Collection:** `visual_intelligence`
- **Type:** Vector Search
- **Configuration:**

```json
{
  "fields": [
    { "type": "vector", "path": "embedding", "numDimensions": 1024, "similarity": "cosine" },
    { "type": "filter", "path": "brandName" },
    { "type": "filter", "path": "type" }
  ]
}
```

#### 5f. `infrastructure_intel` — Atlas Search Index

- **Index Name:** `infra_search_index`
- **Collection:** `infrastructure_intel`
- **Configuration:**

```json
{
  "mappings": {
    "dynamic": false,
    "fields": {
      "domain": { "type": "string", "analyzer": "lucene.keyword" },
      "asn": { "type": "string", "analyzer": "lucene.keyword" },
      "asnName": { "type": "string", "analyzer": "lucene.standard" },
      "hostingProvider": { "type": "string", "analyzer": "lucene.keyword" },
      "status": { "type": "stringFacet" },
      "geoCountry": { "type": "stringFacet" },
      "ipRotationCount24h": { "type": "number" },
      "tlsSelfSigned": { "type": "boolean" }
    }
  }
}
```

#### 5g. `behavior_metrics` — Atlas Search Index

- **Index Name:** `behavior_search_index`
- **Collection:** `behavior_metrics`
- **Configuration:**

```json
{
  "mappings": {
    "dynamic": false,
    "fields": {
      "domain": { "type": "string", "analyzer": "lucene.keyword" },
      "anomalyType": { "type": "string", "analyzer": "lucene.keyword" },
      "isAnomaly": { "type": "boolean" },
      "requestsPerMinute": { "type": "number" },
      "zScoreRpm": { "type": "number" }
    }
  }
}
```

> **Important:** Wait for all indexes to show status **Active** before proceeding. This typically takes 1–2 minutes per index.

---

### Step 6: Start the Backend

```bash
cd backend
poetry run uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`. You can verify it's running by visiting `http://localhost:8000/docs` (Swagger UI).

---

### Step 7: Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:3000`.

---

### Alternative: Docker Compose (One Command Setup)

If you prefer running everything in containers:

```bash
docker-compose up --build
```

This starts both services:
- **Frontend:** `http://localhost:3000`
- **Backend:** `http://localhost:8000`

> **Note:** You still need to create Atlas Search indexes manually (Step 5) and have your `.env` file configured (Step 2).

---

## Verification Checklist

After setup, verify everything works:

| Check | How |
|---|---|
| Backend is running | Visit `http://localhost:8000/docs` — Swagger UI loads |
| Database is seeded | `GET http://localhost:8000/api/v1/dashboard/stats` returns counts > 0 |
| Atlas Search works | Go to `/search` page, run a text query like "phishing login" |
| Vector Search works | Go to `/search` page, run a semantic query (requires embeddings) |
| Frontend loads | Visit `http://localhost:3000` — Dashboard with stats appears |
| URL Scanner works | Go to `/scan`, enter any URL, click Scan |

---

## Pages

| Route | Description |
|-------|-------------|
| `/` | Dashboard with stats, trends, recent activity |
| `/scan` | Real-time URL scanner with risk scoring |
| `/threats` | Threat database with Atlas Search & filters |
| `/search` | Search playground comparing Atlas/Vector/Hybrid |
| `/analytics` | Charts and analytics |
| `/settings` | System health and index tests |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Analyze a URL |
| `POST` | `/api/v1/scan/agentic` | Analyze a URL and add Foundry reasoning |
| `GET` | `/api/v1/urls` | List URLs |
| `GET` | `/api/v1/urls/:id` | URL detail |
| `PATCH` | `/api/v1/urls/:id/status` | Update status |
| `GET` | `/api/v1/dashboard/stats` | Dashboard stats |
| `GET` | `/api/v1/dashboard/trends` | Trend data |
| `GET` | `/api/v1/threat-logs` | Threat logs |
| `POST` | `/api/v1/search/atlas` | Atlas Search |
| `POST` | `/api/v1/search/vector` | Vector Search |
| `POST` | `/api/v1/search/hybrid` | Hybrid Search |
| `POST` | `/api/v1/search/unified` | Unified Search |
| `GET` | `/api/v1/search/demo-scenarios` | Demo scenarios |

## Tech Stack

- **Frontend**: Next.js 15, React 18, MongoDB LeafyGreen UI, Recharts
- **Backend**: FastAPI, Motor, Pydantic, Poetry
- **Database**: MongoDB Atlas
- **Search**: Atlas Search + Vector Search + $rankFusion Hybrid
- **Embeddings**: Voyage AI (voyage-3, 1024 dimensions)
- **Containerization**: Docker + Docker Compose

## Troubleshooting

| Issue | Solution |
|---|---|
| `poetry: command not found` | Run `pip install poetry` or `pipx install poetry` |
| `MONGODB_URI` connection error | Ensure your Atlas cluster allows connections from your IP (Network Access → Add Current IP) |
| Search returns no results | Verify indexes are **Active** in Atlas UI; re-run seed if needed |
| Vector Search returns empty | Ensure `VOYAGE_AI_API_KEY` was set before seeding; re-run `poetry run python -m scripts.seed_data` |
| Frontend can't reach backend | Ensure backend is running on port 8000; check `NEXT_PUBLIC_API_URL` if using Docker |
| Port already in use | Kill existing process: `lsof -ti:8000 | xargs kill` or change port in `.env` |
