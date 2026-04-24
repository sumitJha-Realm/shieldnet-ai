"""Unified Search routes."""

from fastapi import APIRouter, Depends
from models.search import HybridSearchRequest, UnifiedSearchRequest, SearchType
from services.dependencies import get_hybrid_search_service, get_unified_search_service
from services.search.hybrid_search_service import HybridSearchService
from services.search.unified_search_service import UnifiedSearchService

router = APIRouter(tags=["Unified Search"])


@router.post("/hybrid")
async def hybrid_search(
    request: HybridSearchRequest,
    service: HybridSearchService = Depends(get_hybrid_search_service),
):
    """Hybrid Search — $rankFusion combining Atlas + Vector with configurable weights."""
    return await service.search(
        query=request.query,
        filters=request.filters,
        atlas_weight=request.atlasWeight,
        vector_weight=request.vectorWeight,
        limit=request.limit,
    )


@router.post("/unified")
async def unified_search(
    request: UnifiedSearchRequest,
    service: UnifiedSearchService = Depends(get_unified_search_service),
):
    """Unified Search — orchestrates all search methods."""
    return await service.search(
        query=request.query,
        search_types=request.searchTypes,
        filters=request.filters,
        limit=request.limit,
    )


@router.get("/demo-scenarios")
async def demo_scenarios(
    service: UnifiedSearchService = Depends(get_unified_search_service),
):
    """Predefined demo scenarios showcasing each search type."""
    return service.get_demo_scenarios()
