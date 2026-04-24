"""Debug routes for search index testing."""

from fastapi import APIRouter, Depends
from services.dependencies import (
    get_atlas_search_service,
    get_vector_search_service,
    get_database,
)
from services.search.atlas_search_service import AtlasSearchService
from services.search.vector_search_service import VectorSearchService

router = APIRouter(tags=["Search Debug"])


@router.get("/info")
async def search_info(
    atlas_svc: AtlasSearchService = Depends(get_atlas_search_service),
    vector_svc: VectorSearchService = Depends(get_vector_search_service),
):
    """Search index status, vector stats, service health."""
    db = get_database()
    urls_count = await db["urls"].count_documents({})
    urls_with_embedding = await db["urls"].count_documents({"embedding": {"$exists": True, "$ne": None}})

    return {
        "database": db.name,
        "urlsCollection": {
            "totalDocuments": urls_count,
            "documentsWithEmbedding": urls_with_embedding,
        },
        "services": {
            "atlasSearch": "initialized",
            "vectorSearch": "initialized",
            "hybridSearch": "initialized",
        },
    }


@router.post("/atlas/test-index")
async def test_atlas_index(
    service: AtlasSearchService = Depends(get_atlas_search_service),
):
    """Test Atlas Search index connectivity."""
    return await service.test_index()


@router.post("/vector/test-index")
async def test_vector_index(
    service: VectorSearchService = Depends(get_vector_search_service),
):
    """Test Vector Search index connectivity."""
    return await service.test_index()
