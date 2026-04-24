"""Vector Search routes."""

from fastapi import APIRouter, Depends
from models.search import VectorSearchRequest
from services.dependencies import get_vector_search_service
from services.search.vector_search_service import VectorSearchService

router = APIRouter(tags=["Vector Search"])


@router.post("/vector")
async def vector_search(
    request: VectorSearchRequest,
    service: VectorSearchService = Depends(get_vector_search_service),
):
    """Vector Search — semantic similarity using Voyage AI embedding of query."""
    return await service.search(
        query=request.query,
        filters=request.filters,
        num_candidates=request.numCandidates,
        limit=request.limit,
    )
