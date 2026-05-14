"""Batch scan endpoint for SOC use (UC 9)."""

import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from services.dependencies import get_url_analysis_service
from services.url_analysis_service import URLAnalysisService

router = APIRouter(tags=["Batch Scanning"])


class BatchScanItem(BaseModel):
    url: str
    pageContent: str = Field(default="")


class BatchScanRequest(BaseModel):
    urls: list[str | BatchScanItem]


@router.post("/scan/batch")
async def batch_scan(
    request: BatchScanRequest,
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Batch scan multiple URLs (UC 9: SOC bulk scanning).

    Accepts up to 20 URLs per request for POC.
    Each URL goes through the full analysis pipeline.
    """
    urls = request.urls[:20]  # POC limit

    if not urls:
        raise HTTPException(status_code=400, detail="No URLs provided")

    results = []
    errors = []

    for item in urls:
        if isinstance(item, str):
            url = item
            page_content = ""
        else:
            url = item.url
            page_content = item.pageContent
        try:
            result = await service.scan_url(url, page_content=page_content)
            results.append({
                "url": url,
                "pageContentProvided": bool(page_content),
                "riskScore": result.get("urlRecord", {}).get("riskScore", 0),
                "threatClassification": result.get("urlRecord", {}).get("threatClassification", "unknown"),
                "status": result.get("urlRecord", {}).get("status", "unknown"),
                "recommendedAction": result.get("recommendedAction", "review"),
                "riskLevel": result.get("riskLevel", "unknown"),
                "waterfallTier": result.get("waterfallTier", ""),
            })
        except Exception as e:
            errors.append({"url": url, "error": str(e)})

    high_risk = [r for r in results if r["riskScore"] >= 80]
    medium_risk = [r for r in results if 50 <= r["riskScore"] < 80]
    low_risk = [r for r in results if r["riskScore"] < 50]

    return {
        "totalScanned": len(results),
        "totalErrors": len(errors),
        "summary": {
            "high_risk": len(high_risk),
            "medium_risk": len(medium_risk),
            "low_risk": len(low_risk),
        },
        "results": results,
        "errors": errors,
        "threats": high_risk,
    }


@router.post("/scan/batch/csv")
async def batch_scan_csv(
    file: UploadFile = File(...),
    service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Upload CSV file with URLs for batch scanning.

    CSV should have URLs in the first column (with or without header).
    Optional second column may contain pageContent.
    """
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a .csv")

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.reader(io.StringIO(text))
    urls: list[str | BatchScanItem] = []
    for row in reader:
        if row and row[0].strip():
            url = row[0].strip()
            # Skip header-like rows
            if url.lower() in ("url", "urls", "link", "links", "address"):
                continue
            page_content = row[1].strip() if len(row) > 1 else ""
            if page_content:
                urls.append(BatchScanItem(url=url, pageContent=page_content))
            else:
                urls.append(url)

    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in CSV")

    # Reuse the batch scan logic
    request = BatchScanRequest(urls=urls[:20])
    return await batch_scan(request, service)
