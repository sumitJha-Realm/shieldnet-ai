"""Multi-collection repository for cross-collection search operations.

Handles:
- Vector search on threat_signals, regional_threats, visual_intelligence
- Atlas Search (range/compound) on infrastructure_intel, behavior_metrics
- Parallel fan-out across collections via asyncio.gather
"""

import asyncio
import logging
import time
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


class MultiCollectionRepository:
    """Repository for querying across all 5 threat detection collections."""

    # Collection name → vector index name (only for vector-enabled collections)
    VECTOR_INDEXES = {
        "threat_signals": "vs_threat_signals",
        "regional_threats": "vs_regional",
        "visual_intelligence": "vs_visual",
    }

    # Atlas Search indexes (for non-vector collections)
    SEARCH_INDEXES = {
        "infrastructure_intel": "infra_search_index",
        "behavior_metrics": "behavior_search_index",
    }

    def __init__(self, db: AsyncIOMotorDatabase):
        self._db = db

    # ─── Vector Search (threat_signals, regional_threats, visual_intelligence) ───

    async def vector_search(
        self,
        collection_name: str,
        query_vector: list[float],
        limit: int = 10,
        num_candidates: int = 100,
        filters: Optional[dict] = None,
        embedding_path: str = "embedding",
        index_name: Optional[str] = None,
    ) -> list[dict]:
        """Run $vectorSearch on a single collection."""
        idx = index_name or self.VECTOR_INDEXES.get(collection_name)
        if not idx:
            logger.warning("No vector index configured for collection: %s", collection_name)
            return []

        vs_stage: dict = {
            "$vectorSearch": {
                "index": idx,
                "path": embedding_path,
                "queryVector": query_vector,
                "numCandidates": num_candidates,
                "limit": limit,
            }
        }
        if filters:
            vs_stage["$vectorSearch"]["filter"] = filters

        pipeline = [
            vs_stage,
            {"$addFields": {
                "vectorScore": {"$meta": "vectorSearchScore"},
                "_collection": collection_name,
            }},
            {"$project": {"embedding": 0}},
        ]

        results = []
        try:
            coll = self._db[collection_name]
            async for doc in coll.aggregate(pipeline):
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
                results.append(doc)
        except Exception as e:
            logger.error("Vector search on %s failed: %s", collection_name, e)

        return results

    # ─── Atlas Search on infrastructure_intel (UC 2, 5, 16, 17, 22) ──────────

    async def search_infrastructure(
        self,
        domain: str,
        ip: Optional[str] = None,
        asn: Optional[str] = None,
        check_fast_flux: bool = False,
        check_tls_anomaly: bool = False,
        limit: int = 10,
    ) -> list[dict]:
        """Atlas Search compound query on infrastructure_intel — no embedding needed."""
        must_clauses = []
        should_clauses = []

        # Always search by domain (fuzzy for typosquatting variants)
        must_clauses.append({
            "text": {
                "query": domain,
                "path": ["domain", "redirectDomains"],
                "fuzzy": {"maxEdits": 1}
            }
        })

        # If we have IP/ASN info, boost matches
        if ip:
            should_clauses.append({
                "text": {"query": ip, "path": "resolvedIps"}
            })
        if asn:
            should_clauses.append({
                "text": {"query": asn, "path": "asn"}
            })

        # UC 17: Fast-flux detection — high IP rotation
        if check_fast_flux:
            should_clauses.append({
                "range": {"path": "ipRotationCount24h", "gte": 5}
            })
            should_clauses.append({
                "range": {"path": "ttlSeconds", "lte": 300}
            })

        # UC 16: TLS anomalies
        if check_tls_anomaly:
            should_clauses.append({
                "text": {"query": "self-signed expired unknown", "path": "tlsIssuer"}
            })

        search_stage: dict = {
            "$search": {
                "index": self.SEARCH_INDEXES["infrastructure_intel"],
                "compound": {"must": must_clauses}
            }
        }
        if should_clauses:
            search_stage["$search"]["compound"]["should"] = should_clauses
            search_stage["$search"]["compound"]["minimumShouldMatch"] = 1

        pipeline = [
            search_stage,
            {"$limit": limit},
            {"$addFields": {
                "searchScore": {"$meta": "searchScore"},
                "_collection": "infrastructure_intel",
            }},
        ]

        results = []
        try:
            coll = self._db["infrastructure_intel"]
            async for doc in coll.aggregate(pipeline):
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
                results.append(doc)
        except Exception as e:
            logger.error("Infrastructure search failed: %s", e)

        return results

    # ─── Atlas Search on behavior_metrics (UC 9, 20, 25) ─────────────────────

    async def search_behavior(
        self,
        domain: str,
        rpm_threshold: float = 100.0,
        error_rate_threshold: float = 0.3,
        limit: int = 5,
    ) -> list[dict]:
        """Atlas Search range query on behavior_metrics — no embedding needed."""
        pipeline = [
            {
                "$search": {
                    "index": self.SEARCH_INDEXES["behavior_metrics"],
                    "compound": {
                        "must": [
                            {"text": {"query": domain, "path": "domain", "fuzzy": {"maxEdits": 1}}}
                        ],
                        "should": [
                            {"range": {"path": "requestsPerMinute", "gte": rpm_threshold}},
                            {"range": {"path": "errorRate5xx", "gte": error_rate_threshold}},
                            {"range": {"path": "headerEntropy", "lte": 0.2}},
                            {"range": {"path": "avgTimeBetweenRequests", "lte": 50}},
                        ],
                        "minimumShouldMatch": 1,
                    }
                }
            },
            {"$limit": limit},
            {"$addFields": {
                "searchScore": {"$meta": "searchScore"},
                "_collection": "behavior_metrics",
            }},
        ]

        results = []
        try:
            coll = self._db["behavior_metrics"]
            async for doc in coll.aggregate(pipeline):
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
                results.append(doc)
        except Exception as e:
            logger.error("Behavior search failed: %s", e)

        return results

    # ─── Parallel multi-collection search ────────────────────────────────────

    async def search_all_collections(
        self,
        domain: str,
        threat_embedding: Optional[list[float]] = None,
        regional_embedding: Optional[list[float]] = None,
        visual_embedding: Optional[list[float]] = None,
        ip: Optional[str] = None,
        asn: Optional[str] = None,
        has_infra_data: bool = False,
        has_traffic_anomaly: bool = False,
        check_fast_flux: bool = False,
        check_tls_anomaly: bool = False,
    ) -> dict[str, list[dict]]:
        """Fan-out search across all relevant collections in parallel.

        Returns dict mapping collection_name → list of results.
        Only queries collections where we have the needed signals.
        """
        start = time.monotonic()
        tasks = {}

        # ALWAYS: vector search on threat_signals (if we have embedding)
        if threat_embedding:
            tasks["threat_signals"] = self.vector_search(
                "threat_signals", threat_embedding, limit=10
            )

        # CONDITIONAL: regional vector search
        if regional_embedding:
            tasks["regional_threats"] = self.vector_search(
                "regional_threats", regional_embedding, limit=5
            )

        # CONDITIONAL: visual vector search
        if visual_embedding:
            tasks["visual_intelligence"] = self.vector_search(
                "visual_intelligence", visual_embedding, limit=5
            )

        # CONDITIONAL: infrastructure Atlas Search (no embedding)
        if has_infra_data:
            tasks["infrastructure_intel"] = self.search_infrastructure(
                domain=domain,
                ip=ip,
                asn=asn,
                check_fast_flux=check_fast_flux,
                check_tls_anomaly=check_tls_anomaly,
            )

        # CONDITIONAL: behavior Atlas Search (no embedding)
        if has_traffic_anomaly:
            tasks["behavior_metrics"] = self.search_behavior(domain=domain)

        if not tasks:
            return {}

        # Fire all in parallel
        keys = list(tasks.keys())
        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

        results = {}
        for key, result in zip(keys, results_list):
            if isinstance(result, Exception):
                logger.error("Multi-collection search failed for %s: %s", key, result)
                results[key] = []
            else:
                results[key] = result

        elapsed = (time.monotonic() - start) * 1000
        logger.info(
            "Multi-collection search completed in %.2fms (collections: %s)",
            elapsed, ", ".join(keys)
        )

        return results

    # ─── Write operations (for seeding and scan result persistence) ───────────

    async def upsert_threat_signal(self, doc: dict) -> str:
        """Upsert a document into threat_signals collection."""
        coll = self._db["threat_signals"]
        result = await coll.update_one(
            {"url": doc["url"], "attackCategory": doc.get("attackCategory", "")},
            {"$set": doc},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else "updated"

    async def upsert_infrastructure(self, doc: dict) -> str:
        """Upsert a document into infrastructure_intel collection."""
        coll = self._db["infrastructure_intel"]
        result = await coll.update_one(
            {"domain": doc["domain"]},
            {"$set": doc},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else "updated"

    async def upsert_regional_threat(self, doc: dict) -> str:
        """Upsert a document into regional_threats collection."""
        coll = self._db["regional_threats"]
        result = await coll.update_one(
            {"url": doc["url"], "language": doc.get("language", "hi")},
            {"$set": doc},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else "updated"

    async def upsert_visual_intel(self, doc: dict) -> str:
        """Upsert a document into visual_intelligence collection."""
        coll = self._db["visual_intelligence"]
        result = await coll.update_one(
            {"url": doc["url"], "type": doc.get("type", "baseline")},
            {"$set": doc},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else "updated"

    async def upsert_behavior_metrics(self, doc: dict) -> str:
        """Upsert a document into behavior_metrics collection."""
        coll = self._db["behavior_metrics"]
        result = await coll.update_one(
            {"domain": doc["domain"], "anomalyType": doc.get("anomalyType", "")},
            {"$set": doc},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else "updated"
