"""Campaign routes — list and inspect detected campaigns."""

from fastapi import APIRouter, Depends, HTTPException, Query
from services.dependencies import get_campaign_repository
from repositories.impl.campaign_repository import CampaignRepository

router = APIRouter(tags=["Campaigns"])


@router.get("/campaigns")
async def list_campaigns(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = None,
    attack_category: str | None = None,
    repo: CampaignRepository = Depends(get_campaign_repository),
):
    """List detected campaigns, newest first."""
    filt = {}
    if status:
        filt["status"] = status
    if attack_category:
        filt["attackCategory"] = attack_category
    campaigns = await repo.find_many(
        filt, skip=skip, limit=limit, sort=[("lastSeen", -1)]
    )
    total = await repo.count(filt)
    return {"campaigns": campaigns, "total": total}


@router.get("/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
):
    """Get campaign details by ID."""
    campaign = await repo.find_by_id(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign
