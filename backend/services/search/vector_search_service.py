"""Vector Search service."""

import logging
import os
import time

from repositories.impl.vector_search_repository import VectorSearchRepository
from services.embedding_service import get_embedding
from utils.atlas_search_builder import VectorSearchBuilder

logger = logging.getLogger(__name__)

INDEX_NAME = os.getenv("VECTOR_SEARCH_INDEX", "url_vector_index")


class VectorSearchService:
    def __init__(self, search_repo: VectorSearchRepository):
        self._repo = search_repo

    async def search(
        self,
        query: str,
        filters: dict | None = None,
        num_candidates: int = 100,
        limit: int = 10,
    ) -> dict:
        start = time.time()

        query_embedding = await get_embedding(query)

        results = await self.search_similar(
            query_vector=query_embedding,
            filters=filters,
            num_candidates=num_candidates,
            limit=limit,
        )

        elapsed = (time.time() - start) * 1000

        return {
            "results": results,
            "totalResults": len(results),
            "searchType": "vector",
            "executionTimeMs": round(elapsed, 2),
            "query": query,
        }

    async def search_similar(
        self,
        query_vector: list[float],
        filters: dict | None = None,
        num_candidates: int = 100,
        limit: int = 10,
    ) -> list[dict]:
        builder = VectorSearchBuilder(INDEX_NAME)
        builder.with_query_vector(query_vector)
        builder.with_num_candidates(num_candidates)
        builder.with_limit(limit)

        if filters:
            filter_doc = {}
            if "threatClassification" in filters:
                filter_doc["threatClassification"] = filters["threatClassification"]
            if "status" in filters:
                filter_doc["status"] = filters["status"]
            if filter_doc:
                builder.with_filter(filter_doc)

        pipeline = builder.build_pipeline(
            project={"_id": {"$toString": "$_id"}},
        )

        # Exclude embedding from results
        pipeline.append({"$project": {"embedding": 0}})

        return await self._repo.search(pipeline)

    async def test_index(self) -> dict:
        return await self._repo.test_index(INDEX_NAME)
