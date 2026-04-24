from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class SearchType(str, Enum):
    ATLAS = "atlas"
    VECTOR = "vector"
    HYBRID = "hybrid"


class AtlasSearchRequest(BaseModel):
    query: str
    filters: Optional[dict] = None
    fuzzyMaxEdits: int = 2
    limit: int = 20
    offset: int = 0


class VectorSearchRequest(BaseModel):
    query: str
    filters: Optional[dict] = None
    numCandidates: int = 100
    limit: int = 10


class HybridSearchRequest(BaseModel):
    query: str
    filters: Optional[dict] = None
    atlasWeight: float = 0.4
    vectorWeight: float = 0.6
    limit: int = 20


class UnifiedSearchRequest(BaseModel):
    query: str
    searchTypes: list[SearchType] = [SearchType.ATLAS, SearchType.VECTOR, SearchType.HYBRID]
    filters: Optional[dict] = None
    limit: int = 20


class SearchResult(BaseModel):
    id: str
    url: str
    domain: str
    threatClassification: str
    riskScore: float
    status: str
    summaryText: str = ""
    score: float = 0.0
    searchType: str = ""


class SearchScoreDetails(BaseModel):
    atlasScore: Optional[float] = None
    vectorScore: Optional[float] = None
    atlasContribution: Optional[float] = None
    vectorContribution: Optional[float] = None


class HybridSearchResult(SearchResult):
    scoreDetails: Optional[SearchScoreDetails] = None


class SearchResponse(BaseModel):
    results: list[SearchResult] = []
    totalResults: int = 0
    searchType: str = ""
    executionTimeMs: float = 0.0
    query: str = ""


class HybridSearchResponse(BaseModel):
    results: list[HybridSearchResult] = []
    totalResults: int = 0
    searchType: str = "hybrid"
    executionTimeMs: float = 0.0
    query: str = ""
    atlasWeight: float = 0.4
    vectorWeight: float = 0.6


class UnifiedSearchResponse(BaseModel):
    atlas: Optional[SearchResponse] = None
    vector: Optional[SearchResponse] = None
    hybrid: Optional[HybridSearchResponse] = None
    totalExecutionTimeMs: float = 0.0
    query: str = ""


class DemoScenario(BaseModel):
    id: str
    name: str
    description: str
    query: str
    searchType: SearchType
    expectedBehavior: str
