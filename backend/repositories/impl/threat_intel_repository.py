"""Threat Intel Feeds repository — vector search against known threat intelligence."""

import logging
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

VECTOR_INDEX = "threat_intel_vector_index"


class ThreatIntelRepository:
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str = "threat_intel_feeds"):
        self._collection = db[collection_name]

    async def vector_search(
        self,
        query_vector: list[float],
        limit: int = 5,
        num_candidates: int = 100,
    ) -> list[dict]:
        pipeline = [
            {
                "$vectorSearch": {
                    "index": VECTOR_INDEX,
                    "path": "embedding",
                    "queryVector": query_vector,
                    "numCandidates": num_candidates,
                    "limit": limit,
                }
            },
            {"$addFields": {"score": {"$meta": "vectorSearchScore"}}},
            {"$project": {"embedding": 0}},
        ]
        results = []
        try:
            async for doc in self._collection.aggregate(pipeline):
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
                results.append(doc)
        except Exception as e:
            logger.error("Threat intel vector search failed: %s", e)
            raise
        return results
