"""URL Scanner routes."""

from fastapi import APIRouter, Depends, HTTPException
from models.url_analysis import URLScanRequest
from services.agentic_analysis_service import AgenticAnalysisService
from services.dependencies import get_agentic_analysis_service, get_url_analysis_service
from services.url_analysis_service import URLAnalysisService

router = APIRouter(tags=["URL Scanner"])


@router.post("/scan")
async def scan_url(
    request: URLScanRequest,
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Submit a URL for real-time analysis."""
    try:
        result = await service.scan_url(request.url, page_content=request.pageContent)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/agentic")
async def scan_url_agentic(
    request: URLScanRequest,
    service: AgenticAnalysisService = Depends(get_agentic_analysis_service),
):
    """Submit a URL for deterministic scan plus Foundry reasoning."""
    try:
        return await service.scan_url(request.url, page_content=request.pageContent)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/urls")
async def list_urls(
    skip: int = 0,
    limit: int = 20,
    status: str | None = None,
    classification: str | None = None,
    domain: str | None = None,
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """List all analyzed URLs with pagination. Filter by status, classification, or baseDomain."""
    return await service.list_urls(skip=skip, limit=limit, status=status, classification=classification, domain=domain)


@router.get("/urls/{url_id}")
async def get_url(
    url_id: str,
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Get URL analysis detail."""
    result = await service.get_url(url_id)
    if not result:
        raise HTTPException(status_code=404, detail="URL not found")
    return result


@router.get("/cache/stats")
async def cache_stats(
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Return waterfall cache performance statistics."""
    return service.get_cache_stats()
