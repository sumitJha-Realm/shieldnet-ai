"""URL Behavior Enricher API route."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from enricher.enricher import enrich_url

router = APIRouter(tags=["URL Behavior Enricher"])


class EnrichRequest(BaseModel):
    url: str


@router.post("/enrich")
async def enrich_url_endpoint(request: EnrichRequest):
    """Run full behavioral enrichment pipeline on a URL.

    Returns both structured JSON profile and natural language narrative
    suitable for embedding model input.
    """
    try:
        result = await enrich_url(request.url)
        return result.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
