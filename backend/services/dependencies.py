"""FastAPI dependency injection — singleton pattern for services."""

import os
import logging
from functools import lru_cache

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from repositories.impl.url_repository import URLRepository
from repositories.impl.atlas_search_repository import AtlasSearchRepository
from repositories.impl.vector_search_repository import VectorSearchRepository
from repositories.impl.scan_rules_repository import ScanRulesRepository
from repositories.impl.url_graph_repository import URLGraphRepository
from repositories.impl.campaign_repository import CampaignRepository
from services.agentic_analysis_service import AgenticAnalysisService
from services.campaign_detection_service import CampaignDetectionService
from services.url_analysis_service import URLAnalysisService
from services.url_graph_service import URLGraphService
from services.search.atlas_search_service import AtlasSearchService
from services.search.vector_search_service import VectorSearchService
from services.search.hybrid_search_service import HybridSearchService
from services.search.unified_search_service import UnifiedSearchService

from services.waterfall_cache import WaterfallCache

logger = logging.getLogger(__name__)

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None
_waterfall_cache: WaterfallCache | None = None


def get_waterfall_cache() -> WaterfallCache:
    global _waterfall_cache
    if _waterfall_cache is None:
        _waterfall_cache = WaterfallCache(max_size=10_000, ttl_secs=300)
    return _waterfall_cache


def get_mongo_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        _client = AsyncIOMotorClient(uri)
        logger.info("MongoDB client initialized")
    return _client


def get_database() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        client = get_mongo_client()
        db_name = os.getenv("DB_NAME", "shieldnet-ai")
        _db = client[db_name]
        logger.info("Using database: %s", db_name)
    return _db


# --- Repository singletons ---

_url_repo: URLRepository | None = None
_atlas_search_repo: AtlasSearchRepository | None = None
_vector_search_repo: VectorSearchRepository | None = None


def get_url_repository() -> URLRepository:
    global _url_repo
    if _url_repo is None:
        _url_repo = URLRepository(get_database())
    return _url_repo


def get_atlas_search_repository() -> AtlasSearchRepository:
    global _atlas_search_repo
    if _atlas_search_repo is None:
        _atlas_search_repo = AtlasSearchRepository(get_database())
    return _atlas_search_repo


def get_vector_search_repository() -> VectorSearchRepository:
    global _vector_search_repo
    if _vector_search_repo is None:
        _vector_search_repo = VectorSearchRepository(get_database())
    return _vector_search_repo


_scan_rules_repo: ScanRulesRepository | None = None


def get_scan_rules_repository() -> ScanRulesRepository:
    global _scan_rules_repo
    if _scan_rules_repo is None:
        _scan_rules_repo = ScanRulesRepository(get_database())
    return _scan_rules_repo


_campaign_repo: CampaignRepository | None = None


def get_campaign_repository() -> CampaignRepository:
    global _campaign_repo
    if _campaign_repo is None:
        _campaign_repo = CampaignRepository(get_database())
    return _campaign_repo


# --- Service singletons ---

_campaign_detection_svc: CampaignDetectionService | None = None


def get_campaign_detection_service() -> CampaignDetectionService:
    global _campaign_detection_svc
    if _campaign_detection_svc is None:
        _campaign_detection_svc = CampaignDetectionService(get_campaign_repository())
    return _campaign_detection_svc


_atlas_search_svc: AtlasSearchService | None = None
_vector_search_svc: VectorSearchService | None = None
_hybrid_search_svc: HybridSearchService | None = None
_unified_search_svc: UnifiedSearchService | None = None
_url_analysis_svc: URLAnalysisService | None = None
_agentic_analysis_svc: AgenticAnalysisService | None = None


def get_atlas_search_service() -> AtlasSearchService:
    global _atlas_search_svc
    if _atlas_search_svc is None:
        _atlas_search_svc = AtlasSearchService(get_atlas_search_repository())
    return _atlas_search_svc


def get_vector_search_service() -> VectorSearchService:
    global _vector_search_svc
    if _vector_search_svc is None:
        _vector_search_svc = VectorSearchService(get_vector_search_repository())
    return _vector_search_svc


def get_hybrid_search_service() -> HybridSearchService:
    global _hybrid_search_svc
    if _hybrid_search_svc is None:
        _hybrid_search_svc = HybridSearchService(get_atlas_search_repository())
    return _hybrid_search_svc


def get_unified_search_service() -> UnifiedSearchService:
    global _unified_search_svc
    if _unified_search_svc is None:
        _unified_search_svc = UnifiedSearchService(
            get_atlas_search_service(),
            get_vector_search_service(),
            get_hybrid_search_service(),
        )
    return _unified_search_svc


def get_url_analysis_service() -> URLAnalysisService:
    global _url_analysis_svc
    if _url_analysis_svc is None:
        _url_analysis_svc = URLAnalysisService(
            url_repo=get_url_repository(),
            vector_search_service=get_vector_search_service(),
            atlas_search_service=get_atlas_search_service(),
            cache=get_waterfall_cache(),
            rules_repo=get_scan_rules_repository(),
            graph_service=get_url_graph_service(),
            campaign_service=get_campaign_detection_service(),
        )
    return _url_analysis_svc


def get_agentic_analysis_service() -> AgenticAnalysisService:
    global _agentic_analysis_svc
    if _agentic_analysis_svc is None:
        _agentic_analysis_svc = AgenticAnalysisService(get_url_analysis_service())
    return _agentic_analysis_svc


_url_graph_repo: URLGraphRepository | None = None
_url_graph_svc: URLGraphService | None = None


def get_url_graph_repository() -> URLGraphRepository:
    global _url_graph_repo
    if _url_graph_repo is None:
        _url_graph_repo = URLGraphRepository(get_database())
    return _url_graph_repo


def get_url_graph_service() -> URLGraphService:
    global _url_graph_svc
    if _url_graph_svc is None:
        _url_graph_svc = URLGraphService(get_url_graph_repository())
    return _url_graph_svc


async def close_mongo_client():
    global _client
    if _client:
        _client.close()
        _client = None
        logger.info("MongoDB client closed")
