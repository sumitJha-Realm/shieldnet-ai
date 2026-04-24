"""Atlas Search service."""

import logging
import os
import time

from repositories.impl.atlas_search_repository import AtlasSearchRepository
from utils.atlas_search_builder import AtlasSearchBuilder

logger = logging.getLogger(__name__)

INDEX_NAME = os.getenv("ATLAS_SEARCH_INDEX", "url_search_index")


class AtlasSearchService:
    def __init__(self, search_repo: AtlasSearchRepository):
        self._repo = search_repo

    async def search(
        self,
        query: str,
        filters: dict | None = None,
        fuzzy_max_edits: int = 2,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        start = time.time()

        builder = AtlasSearchBuilder(INDEX_NAME)
        builder.must(
            builder.text(
                query,
                path=["url", "domain", "summaryText"],
                fuzzy={"maxEdits": fuzzy_max_edits, "prefixLength": 2},
            )
        )

        if filters:
            if "threatClassification" in filters:
                builder.filter(builder.equals("threatClassification", filters["threatClassification"]))
            if "status" in filters:
                builder.filter(builder.equals("status", filters["status"]))
            if "dnsStatus" in filters:
                builder.filter(builder.equals("dnsStatus", filters["dnsStatus"]))
            if "riskScoreMin" in filters or "riskScoreMax" in filters:
                builder.filter(
                    builder.range(
                        "riskScore",
                        gte=filters.get("riskScoreMin"),
                        lte=filters.get("riskScoreMax"),
                    )
                )

        builder.with_highlight(["url", "domain", "summaryText"])

        pipeline = builder.build_pipeline(
            skip=offset,
            limit=limit,
            project={"_id": {"$toString": "$_id"}},
        )

        # Exclude embedding from results
        pipeline.append({"$project": {"embedding": 0}})

        results = await self._repo.search(pipeline)
        elapsed = (time.time() - start) * 1000

        return {
            "results": results,
            "totalResults": len(results),
            "searchType": "atlas",
            "executionTimeMs": round(elapsed, 2),
            "query": query,
        }

    async def get_facets(self, query: str) -> dict:
        builder = AtlasSearchBuilder(INDEX_NAME)
        facets = {
            "threatClassification": {"type": "string", "path": "threatClassification"},
            "dnsStatus": {"type": "string", "path": "dnsStatus"},
            "status": {"type": "string", "path": "status"},
        }
        operator = {"text": {"query": query, "path": ["url", "domain", "summaryText"]}} if query else None
        pipeline = [builder.build_facet_stage(facets, operator)]
        results = await self._repo.search(pipeline)
        return results[0] if results else {}

    async def test_index(self) -> dict:
        return await self._repo.test_index(INDEX_NAME)
