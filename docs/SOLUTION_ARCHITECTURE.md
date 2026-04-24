# Solution Architecture

## Overview

ShieldNet AI is a real-time malicious URL detection platform designed for NIC (National Informatics Centre) government security operations. It combines traditional text search, semantic AI, and hybrid rank fusion to provide comprehensive threat detection.

## System Components

### Frontend (Next.js 15)
- **App Router** with server-side rendering capability
- **MongoDB LeafyGreen UI** design system for consistent MongoDB-branded interface
- **Custom proxy server** (`server.js`) routes `/api/*` requests to the FastAPI backend
- **Recharts** for interactive data visualizations

### Backend (FastAPI)
- **Repository Pattern**: Abstract interfaces with concrete MongoDB implementations
- **Service Layer**: Business logic separated from data access and route handling
- **Dependency Injection**: Singleton services via FastAPI `Depends()`
- **Fluent Builder Pattern**: `AtlasSearchBuilder`, `VectorSearchBuilder`, `HybridSearchBuilder` for constructing aggregation pipelines

### MongoDB Atlas
- **urls** collection: Core URL analysis records with embeddings
- **threat_logs** collection: Activity audit trail
- **threat_intel_feeds** collection: External threat intelligence

### Voyage AI
- Model: `voyage-3` (1024 dimensions)
- Used for generating embeddings from URL analysis summaries
- Supports batch embedding for seed data generation

## Search Architecture

### Atlas Search (Text)
- Fuzzy text matching across `url`, `domain`, `summaryText` fields
- Faceted filtering on `threatClassification`, `dnsStatus`, `status`
- Highlight support for matched terms

### Vector Search (Semantic)
- Cosine similarity on 1024-dimensional Voyage AI embeddings
- Pre-filtering on `threatClassification` and `status`
- Used during URL scanning to find similar known threats

### Hybrid Search ($rankFusion)
- Combines Atlas Search and Vector Search sub-pipelines
- Configurable weights (default: 40% Atlas, 60% Vector)
- `scoreDetails` enabled to show contribution percentages

## URL Scanning Flow

1. **Feature Extraction** — Parse URL structure, simulate DNS/hosting lookups
2. **Summary Generation** — Build natural language description
3. **Embedding** — Call Voyage AI API for 1024-dim vector
4. **Vector Search** — Find top 5 similar known threats
5. **Risk Scoring** — Weighted formula across all features + similarity
6. **Persist & Respond** — Store in MongoDB, return analysis results
