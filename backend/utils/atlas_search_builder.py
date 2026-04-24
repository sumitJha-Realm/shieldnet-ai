"""Fluent builder for MongoDB Atlas Search aggregation pipelines."""

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AtlasSearchBuilder:
    """Fluent builder pattern for constructing Atlas Search aggregation stages."""

    def __init__(self, index_name: str):
        self._index = index_name
        self._compound: dict[str, list] = {}
        self._highlight: Optional[dict] = None
        self._count_type: Optional[str] = None
        self._facets: Optional[dict] = None
        self._return_stored_source: bool = False
        self._score_details: bool = False

    def must(self, clause: dict) -> "AtlasSearchBuilder":
        self._compound.setdefault("must", []).append(clause)
        return self

    def must_not(self, clause: dict) -> "AtlasSearchBuilder":
        self._compound.setdefault("mustNot", []).append(clause)
        return self

    def should(self, clause: dict) -> "AtlasSearchBuilder":
        self._compound.setdefault("should", []).append(clause)
        return self

    def filter(self, clause: dict) -> "AtlasSearchBuilder":
        self._compound.setdefault("filter", []).append(clause)
        return self

    def text(self, query: str, path: str | list[str], fuzzy: Optional[dict] = None) -> dict:
        clause: dict[str, Any] = {"text": {"query": query, "path": path}}
        if fuzzy:
            clause["text"]["fuzzy"] = fuzzy
        return clause

    def range(self, path: str, gte: Any = None, lte: Any = None) -> dict:
        range_clause: dict[str, Any] = {"range": {"path": path}}
        if gte is not None:
            range_clause["range"]["gte"] = gte
        if lte is not None:
            range_clause["range"]["lte"] = lte
        return range_clause

    def equals(self, path: str, value: Any) -> dict:
        return {"equals": {"path": path, "value": value}}

    def with_highlight(self, paths: list[str], max_chars_to_examine: int = 500000) -> "AtlasSearchBuilder":
        self._highlight = {
            "path": paths,
            "maxCharsToExamine": max_chars_to_examine,
        }
        return self

    def with_score_details(self, enabled: bool = True) -> "AtlasSearchBuilder":
        self._score_details = enabled
        return self

    def with_count(self, count_type: str = "total") -> "AtlasSearchBuilder":
        self._count_type = count_type
        return self

    def build_search_stage(self) -> dict:
        search_stage: dict[str, Any] = {
            "$search": {
                "index": self._index,
                "compound": self._compound,
            }
        }
        if self._highlight:
            search_stage["$search"]["highlight"] = self._highlight
        if self._score_details:
            search_stage["$search"]["scoreDetails"] = True
        if self._count_type:
            search_stage["$search"]["count"] = {"type": self._count_type}
        return search_stage

    def build_facet_stage(self, facets: dict, operator: Optional[dict] = None) -> dict:
        facet_stage: dict[str, Any] = {
            "$searchMeta": {
                "index": self._index,
                "facet": {"facets": facets},
            }
        }
        if operator:
            facet_stage["$searchMeta"]["facet"]["operator"] = operator
        return facet_stage

    def build_pipeline(
        self,
        project: Optional[dict] = None,
        sort: Optional[dict] = None,
        skip: int = 0,
        limit: int = 20,
        additional_stages: Optional[list[dict]] = None,
    ) -> list[dict]:
        pipeline = [self.build_search_stage()]

        if additional_stages:
            pipeline.extend(additional_stages)

        if project:
            pipeline.append({"$addFields": project})

        pipeline.append({"$addFields": {"score": {"$meta": "searchScore"}}})

        if self._score_details:
            pipeline.append({"$addFields": {"scoreDetails": {"$meta": "searchScoreDetails"}}})

        if sort:
            pipeline.append({"$sort": sort})

        if skip > 0:
            pipeline.append({"$skip": skip})

        pipeline.append({"$limit": limit})

        logger.debug("Built Atlas Search pipeline: %s", pipeline)
        return pipeline


class VectorSearchBuilder:
    """Builder for MongoDB Vector Search aggregation stages."""

    def __init__(self, index_name: str, path: str = "embedding"):
        self._index = index_name
        self._path = path
        self._query_vector: list[float] = []
        self._num_candidates: int = 100
        self._limit: int = 10
        self._filter: Optional[dict] = None

    def with_query_vector(self, vector: list[float]) -> "VectorSearchBuilder":
        self._query_vector = vector
        return self

    def with_num_candidates(self, n: int) -> "VectorSearchBuilder":
        self._num_candidates = n
        return self

    def with_limit(self, n: int) -> "VectorSearchBuilder":
        self._limit = n
        return self

    def with_filter(self, filter_doc: dict) -> "VectorSearchBuilder":
        self._filter = filter_doc
        return self

    def build_search_stage(self) -> dict:
        stage: dict[str, Any] = {
            "$vectorSearch": {
                "index": self._index,
                "path": self._path,
                "queryVector": self._query_vector,
                "numCandidates": self._num_candidates,
                "limit": self._limit,
            }
        }
        if self._filter:
            stage["$vectorSearch"]["filter"] = self._filter
        return stage

    def build_pipeline(
        self,
        project: Optional[dict] = None,
        additional_stages: Optional[list[dict]] = None,
    ) -> list[dict]:
        pipeline = [self.build_search_stage()]

        pipeline.append({"$addFields": {"score": {"$meta": "vectorSearchScore"}}})

        if additional_stages:
            pipeline.extend(additional_stages)

        if project:
            pipeline.append({"$addFields": project})

        logger.debug("Built Vector Search pipeline: %s", pipeline)
        return pipeline


class HybridSearchBuilder:
    """Builder for MongoDB Hybrid Search using $rankFusion."""

    def __init__(self):
        self._pipelines: dict[str, list[dict]] = {}
        self._weights: dict[str, float] = {}
        self._limit: int = 20
        self._score_details: bool = True

    def add_pipeline(self, name: str, pipeline: list[dict], weight: float = 1.0) -> "HybridSearchBuilder":
        self._pipelines[name] = pipeline
        self._weights[name] = weight
        return self

    def with_limit(self, n: int) -> "HybridSearchBuilder":
        self._limit = n
        return self

    def with_score_details(self, enabled: bool = True) -> "HybridSearchBuilder":
        self._score_details = enabled
        return self

    def build_pipeline(self) -> list[dict]:
        pipelines_list = {}
        for name, stages in self._pipelines.items():
            pipelines_list[name] = stages

        rank_fusion_stage = {
            "$rankFusion": {
                "input": {
                    "pipelines": pipelines_list,
                },
                "combination": {
                    "weights": self._weights,
                },
            }
        }

        if self._score_details:
            rank_fusion_stage["$rankFusion"]["scoreDetails"] = True

        pipeline = [rank_fusion_stage]
        pipeline.append({"$addFields": {"score": {"$meta": "score"}}})

        if self._score_details:
            pipeline.append({"$addFields": {"scoreDetails": {"$meta": "scoreDetails"}}})

        pipeline.append({"$limit": self._limit})

        logger.debug("Built Hybrid Search pipeline: %s", pipeline)
        return pipeline
