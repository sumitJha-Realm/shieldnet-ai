"""Hybrid Search service using $rankFusion."""

import logging
import os
import time

from repositories.impl.atlas_search_repository import AtlasSearchRepository
from services.embedding_service import get_embedding
from utils.atlas_search_builder import AtlasSearchBuilder, VectorSearchBuilder, HybridSearchBuilder

logger = logging.getLogger(__name__)

ATLAS_INDEX = os.getenv("ATLAS_SEARCH_INDEX", "url_search_index")
VECTOR_INDEX = os.getenv("VECTOR_SEARCH_INDEX", "url_vector_index")


class HybridSearchService:
    def __init__(self, search_repo: AtlasSearchRepository):
        self._repo = search_repo

    async def search(
        self,
        query: str,
        filters: dict | None = None,
        atlas_weight: float = 0.4,
        vector_weight: float = 0.6,
        limit: int = 20,
    ) -> dict:
        start = time.time()

        # Generate embedding for vector component
        query_embedding = await get_embedding(query)

        # Build Atlas Search sub-pipeline
        atlas_builder = AtlasSearchBuilder(ATLAS_INDEX)
        atlas_builder.must(
            atlas_builder.text(
                query,
                path=["url", "domain", "summaryText"],
                fuzzy={"maxEdits": 2, "prefixLength": 2},
            )
        )
        atlas_pipeline = [atlas_builder.build_search_stage()]

        # Build Vector Search sub-pipeline
        vector_builder = VectorSearchBuilder(VECTOR_INDEX)
        vector_builder.with_query_vector(query_embedding)
        vector_builder.with_num_candidates(100)
        vector_builder.with_limit(limit)
        vector_pipeline = [vector_builder.build_search_stage()]

        # Build Hybrid using $rankFusion
        hybrid_builder = HybridSearchBuilder()
        hybrid_builder.add_pipeline("atlas", atlas_pipeline, atlas_weight)
        hybrid_builder.add_pipeline("vector", vector_pipeline, vector_weight)
        hybrid_builder.with_limit(limit)
        hybrid_builder.with_score_details(True)

        pipeline = hybrid_builder.build_pipeline()
        pipeline.append({"$addFields": {"_id": {"$toString": "$_id"}}})
        pipeline.append({"$project": {"embedding": 0}})

        results = await self._repo.search(pipeline)
        elapsed = (time.time() - start) * 1000

        return {
            "results": results,
            "totalResults": len(results),
            "searchType": "hybrid",
            "executionTimeMs": round(elapsed, 2),
            "query": query,
            "atlasWeight": atlas_weight,
            "vectorWeight": vector_weight,
        }
