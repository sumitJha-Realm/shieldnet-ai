"""URL relationship graph API routes."""

from fastapi import APIRouter, Query
from services.dependencies import get_url_graph_service

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/url")
async def get_url_graph(
    url: str = Query(..., description="URL to get the relationship graph for"),
    max_depth: int = Query(2, ge=1, le=3, description="Maximum traversal depth"),
    min_strength: float = Query(0.30, ge=0.0, le=1.0, description="Minimum edge strength"),
):
    """Return the relationship graph around a scanned URL.

    Uses MongoDB ``$graphLookup`` to traverse edges up to *max_depth*
    hops, enriching each node with URL metadata.
    """
    svc = get_url_graph_service()
    return await svc.get_url_graph(url, max_depth=max_depth, min_strength=min_strength)
