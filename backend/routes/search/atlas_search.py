"""Atlas Search routes."""

from fastapi import APIRouter, Depends
from models.search import AtlasSearchRequest
from services.dependencies import get_atlas_search_service
from services.search.atlas_search_service import AtlasSearchService

router = APIRouter(tags=["Atlas Search"])


@router.post("/atlas")
async def atlas_search(
    request: AtlasSearchRequest,
    service: AtlasSearchService = Depends(get_atlas_search_service),
):
    """Atlas Search — fuzzy text search on URLs, domains, summaries."""
    return await service.search(
        query=request.query,
        filters=request.filters,
        fuzzy_max_edits=request.fuzzyMaxEdits,
        limit=request.limit,
        offset=request.offset,
    )


@router.post("/atlas/facets")
async def atlas_facets(
    request: AtlasSearchRequest,
    service: AtlasSearchService = Depends(get_atlas_search_service),
):
    """Get faceted counts for Atlas Search results."""
    return await service.get_facets(request.query)
