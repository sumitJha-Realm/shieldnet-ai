"""Unified Search service — orchestrates Atlas, Vector, and Hybrid search."""

import asyncio
import logging
import time

from models.search import SearchType
from services.search.atlas_search_service import AtlasSearchService
from services.search.vector_search_service import VectorSearchService
from services.search.hybrid_search_service import HybridSearchService

logger = logging.getLogger(__name__)

DEMO_SCENARIOS = [
    {
        "id": "fuzzy_typo",
        "name": "Fuzzy Typo Match",
        "description": "Atlas Search handles typos — search 'phising' (misspelled) and find 'phishing' results.",
        "query": "phising logn page",
        "searchType": "atlas",
        "expectedBehavior": "Atlas Search fuzzy matching corrects the typo and returns phishing-related URLs.",
    },
    {
        "id": "semantic_similar",
        "name": "Semantic Similarity",
        "description": "Vector Search finds URLs with similar threat patterns even if exact keywords differ.",
        "query": "credential harvesting fake government portal",
        "searchType": "vector",
        "expectedBehavior": "Vector Search returns phishing URLs targeting government login pages based on semantic similarity.",
    },
    {
        "id": "hybrid_comprehensive",
        "name": "Hybrid Comprehensive",
        "description": "Hybrid Search combines text matching with semantic understanding.",
        "query": "malware download suspicious domain",
        "searchType": "hybrid",
        "expectedBehavior": "Hybrid Search returns results scored by both keyword relevance and semantic similarity.",
    },
    {
        "id": "domain_search",
        "name": "Domain Keyword Search",
        "description": "Atlas Search for exact domain pattern matching.",
        "query": "gov.in.fake-domain.xyz",
        "searchType": "atlas",
        "expectedBehavior": "Atlas Search finds URLs containing this domain pattern.",
    },
    {
        "id": "threat_pattern",
        "name": "Threat Pattern Discovery",
        "description": "Vector Search finds URLs matching a described threat pattern.",
        "query": "recently registered domain with no SSL hosting malicious JavaScript payload",
        "searchType": "vector",
        "expectedBehavior": "Vector Search identifies malware URLs matching the described pattern.",
    },
]


class UnifiedSearchService:
    def __init__(
        self,
        atlas_service: AtlasSearchService,
        vector_service: VectorSearchService,
        hybrid_service: HybridSearchService,
    ):
        self._atlas = atlas_service
        self._vector = vector_service
        self._hybrid = hybrid_service

    async def search(
        self,
        query: str,
        search_types: list[SearchType] | None = None,
        filters: dict | None = None,
        limit: int = 20,
    ) -> dict:
        if search_types is None:
            search_types = [SearchType.ATLAS, SearchType.VECTOR, SearchType.HYBRID]

        start = time.time()
        tasks = {}

        if SearchType.ATLAS in search_types:
            tasks["atlas"] = self._atlas.search(query, filters=filters, limit=limit)
        if SearchType.VECTOR in search_types:
            tasks["vector"] = self._vector.search(query, filters=filters, limit=limit)
        if SearchType.HYBRID in search_types:
            tasks["hybrid"] = self._hybrid.search(query, filters=filters, limit=limit)

        results = {}
        gathered = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        for key, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                logger.error("Search type %s failed: %s", key, result)
                results[key] = None
            else:
                results[key] = result

        elapsed = (time.time() - start) * 1000

        return {
            "atlas": results.get("atlas"),
            "vector": results.get("vector"),
            "hybrid": results.get("hybrid"),
            "totalExecutionTimeMs": round(elapsed, 2),
            "query": query,
        }

    def get_demo_scenarios(self) -> list[dict]:
        return DEMO_SCENARIOS
