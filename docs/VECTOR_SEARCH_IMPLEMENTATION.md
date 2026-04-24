# Vector Search Implementation

## Embedding Model

- **Provider**: Voyage AI
- **Model**: `voyage-3`
- **Dimensions**: 1024
- **API**: `https://api.voyageai.com/v1/embeddings`
- **Similarity**: Cosine

## Embedding Pipeline

### During URL Scan
1. Extract URL features (domain age, SSL, entropy, DNS status, hosting)
2. Build natural language `summaryText` from features
3. Call Voyage AI to embed the summary → 1024-dim vector
4. Store embedding alongside the URL record

### During Search
1. Take user's search query text
2. Call Voyage AI to embed the query → 1024-dim vector
3. Run `$vectorSearch` aggregation against `url_vector_index`
4. Return ranked results by cosine similarity

## MongoDB Vector Search Index

```json
{
  "fields": [
    {
      "type": "vector",
      "path": "embedding",
      "numDimensions": 1024,
      "similarity": "cosine"
    },
    { "type": "filter", "path": "threatClassification" },
    { "type": "filter", "path": "status" }
  ]
}
```

## Vector Search Pipeline (Builder Pattern)

```python
builder = VectorSearchBuilder("url_vector_index")
builder.with_query_vector(embedding)
builder.with_num_candidates(100)
builder.with_limit(10)
builder.with_filter({"threatClassification": "phishing"})
pipeline = builder.build_pipeline()
```

## Hybrid Search ($rankFusion)

Combines Atlas Search (text) and Vector Search (semantic) using MongoDB's `$rankFusion`:

```python
hybrid_builder = HybridSearchBuilder()
hybrid_builder.add_pipeline("atlas", atlas_stages, weight=0.4)
hybrid_builder.add_pipeline("vector", vector_stages, weight=0.6)
hybrid_builder.with_score_details(True)
pipeline = hybrid_builder.build_pipeline()
```

The `scoreDetails` flag enables per-result breakdown showing how much each search type contributed to the final rank.

## Batch Embedding for Seed Data

The seed script uses Voyage AI's batch API to embed all 220+ URL summaries efficiently:
- Batch size: 128 texts per API call
- Timeout: 120 seconds per batch
- Also embeds 50+ threat intel feed descriptions
