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

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Poetry (`pip install poetry`)
- MongoDB Atlas cluster with Search enabled
- Voyage AI API key

### 1. Clone & Configure

```bash
cp .env.example .env
# Edit .env with your MongoDB URI and Voyage AI key
```

### 2. Backend Setup

```bash
cd backend
poetry install
```

### 3. Seed Database

```bash
cd backend
poetry run python -m scripts.seed_data
```

This generates 220+ URL records, 500+ threat logs, and 50+ threat intel feeds. If `VOYAGE_AI_API_KEY` is set, it also generates embeddings via Voyage AI.

### 4. Create Atlas Search Indexes

In MongoDB Atlas UI, create these indexes on the `urls` collection:

**Atlas Search Index** (`url_search_index`):
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

**Vector Search Index** (`url_vector_index`):
```json
{
  "fields": [
    { "type": "vector", "path": "embedding", "numDimensions": 1024, "similarity": "cosine" },
    { "type": "filter", "path": "threatClassification" },
    { "type": "filter", "path": "status" }
  ]
}
```

### 5. Start Backend

```bash
cd backend
poetry run uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

### 7. Docker Compose (Alternative)

```bash
docker-compose up --build
```

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
