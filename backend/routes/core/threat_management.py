"""Threat management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query
from models.url_analysis import StatusUpdateRequest
from services.dependencies import get_url_analysis_service, get_url_repository
from services.url_analysis_service import URLAnalysisService
from repositories.impl.url_repository import URLRepository

router = APIRouter(tags=["Threat Management"])


@router.get("/domains/watched")
async def get_watched_domains(
    url_repo: URLRepository = Depends(get_url_repository),
):
    """Return the list of watched (monitored) base domains with per-domain URL counts
    and threat class breakdown, so the UI can populate a domain shortlist filter."""
    from models.scan_rules import DEFAULT_SCAN_RULES
    watched = DEFAULT_SCAN_RULES.get("watchedDomains", [])

    pipeline = [
        {"$match": {"baseDomain": {"$in": watched}}},
        {
            "$group": {
                "_id": "$baseDomain",
                "total": {"$sum": 1},
                "blocked": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}},
                "under_review": {"$sum": {"$cond": [{"$eq": ["$status", "under_review"]}, 1, 0]}},
                "allowed": {"$sum": {"$cond": [{"$eq": ["$status", "allowed"]}, 1, 0]}},
                "phishing": {"$sum": {"$cond": [{"$eq": ["$threatClassification", "phishing"]}, 1, 0]}},
                "malware": {"$sum": {"$cond": [{"$eq": ["$threatClassification", "malware"]}, 1, 0]}},
                "c2": {"$sum": {"$cond": [{"$eq": ["$threatClassification", "c2"]}, 1, 0]}},
                "suspicious": {"$sum": {"$cond": [{"$eq": ["$threatClassification", "suspicious"]}, 1, 0]}},
                "benign": {"$sum": {"$cond": [{"$eq": ["$threatClassification", "benign"]}, 1, 0]}},
                "avgRiskScore": {"$avg": "$riskScore"},
                "maxRiskScore": {"$max": "$riskScore"},
            }
        },
        {"$sort": {"maxRiskScore": -1, "_id": 1}},
    ]
    stats = await url_repo.aggregate(pipeline)
    stats_map = {s["_id"]: s for s in stats}

    domains = []
    for d in watched:
        s = stats_map.get(d, {})
        domains.append({
            "domain": d,
            "total": s.get("total", 0),
            "blocked": s.get("blocked", 0),
            "under_review": s.get("under_review", 0),
            "allowed": s.get("allowed", 0),
            "threatBreakdown": {
                "phishing": s.get("phishing", 0),
                "malware": s.get("malware", 0),
                "c2": s.get("c2", 0),
                "suspicious": s.get("suspicious", 0),
                "benign": s.get("benign", 0),
            },
            "avgRiskScore": round(s.get("avgRiskScore") or 0, 1),
            "maxRiskScore": round(s.get("maxRiskScore") or 0, 1),
        })

    return {"domains": domains, "total": len(domains)}


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
