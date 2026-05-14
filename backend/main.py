"""ShieldNet AI — FastAPI application entry point."""

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

from routes.core.url_scanner import router as url_scanner_router
from routes.core.threat_management import router as threat_mgmt_router
from routes.core.enricher import router as enricher_router
from routes.core.scan_rules import router as scan_rules_router
from routes.core.url_graph import router as url_graph_router
from routes.core.campaigns import router as campaigns_router
from routes.core.batch_scan import router as batch_scan_router
from routes.search.atlas_search import router as atlas_search_router
from routes.search.vector_search import router as vector_search_router
from routes.search.unified_search import router as unified_search_router
from routes.debug.search_debug import router as debug_router
from services.dependencies import close_mongo_client, get_database, get_url_graph_service, get_campaign_repository

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("ShieldNet AI backend starting up...")
    db = get_database()
    logger.info("Connected to database: %s", db.name)
    skip_startup_indexes = os.getenv("SKIP_STARTUP_INDEXES", "").lower() in {"1", "true", "yes"}
    if skip_startup_indexes:
        logger.info("Skipping startup index initialization")
    else:
        await get_url_graph_service().ensure_indexes()
        logger.info("Graph indexes ensured")
        await get_campaign_repository().ensure_indexes()
        logger.info("Campaign indexes ensured")
    yield
    # Shutdown
    await close_mongo_client()
    logger.info("ShieldNet AI backend shut down.")


app = FastAPI(
    title="ShieldNet AI",
    description="Real-Time Malicious URL Detection Platform for NIC",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_url, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes
app.include_router(url_scanner_router, prefix="/api/v1")
app.include_router(threat_mgmt_router, prefix="/api/v1")
app.include_router(enricher_router, prefix="/api/v1")
app.include_router(scan_rules_router, prefix="/api/v1")
app.include_router(url_graph_router, prefix="/api/v1")
app.include_router(campaigns_router, prefix="/api/v1")
app.include_router(batch_scan_router, prefix="/api/v1")
app.include_router(atlas_search_router, prefix="/api/v1/search")
app.include_router(vector_search_router, prefix="/api/v1/search")
app.include_router(unified_search_router, prefix="/api/v1/search")
app.include_router(debug_router, prefix="/api/v1/debug/search")


@app.get("/")
async def root():
    return {
        "name": "ShieldNet AI",
        "version": "1.0.0",
        "description": "Real-Time Malicious URL Detection Platform",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
