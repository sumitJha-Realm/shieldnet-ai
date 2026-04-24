"""Threat management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query
from models.url_analysis import StatusUpdateRequest
from services.dependencies import get_url_analysis_service, get_url_repository
from services.url_analysis_service import URLAnalysisService
from repositories.impl.url_repository import URLRepository

router = APIRouter(tags=["Threat Management"])


@router.patch("/urls/{url_id}/status")
async def update_url_status(
    url_id: str,
    request: StatusUpdateRequest,
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Update URL status (block/allow/review)."""
    success = await service.update_status(url_id, request.status.value)
    if not success:
        raise HTTPException(status_code=404, detail="URL not found or status unchanged")
    return {"message": "Status updated", "urlId": url_id, "newStatus": request.status.value}


@router.get("/dashboard/stats")
async def dashboard_stats(
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Real-time dashboard statistics."""
    return await service.get_dashboard_stats()


@router.get("/dashboard/trends")
async def dashboard_trends(
    days: int = Query(30, ge=1, le=365),
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Threat trend data."""
    return await service.get_threat_trends(days=days)


@router.get("/threat-logs")
async def get_threat_logs(
    skip: int = 0,
    limit: int = 50,
    url_repo: URLRepository = Depends(get_url_repository),
):
    """Paginated threat activity logs."""
    from services.dependencies import get_database
    db = get_database()
    logs_collection = db["threat_logs"]
    cursor = logs_collection.find().sort("timestamp", -1).skip(skip).limit(limit)
    logs = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if "urlId" in doc:
            doc["urlId"] = str(doc["urlId"])
        logs.append(doc)
    total = await logs_collection.count_documents({})
    return {"logs": logs, "total": total, "skip": skip, "limit": limit}
