"""Vector Search repository implementation."""

import logging
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from repositories.interfaces import SearchRepositoryInterface

logger = logging.getLogger(__name__)


class VectorSearchRepository(SearchRepositoryInterface):
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str = "urls"):
        self._collection = db[collection_name]

    async def search(self, pipeline: list[dict]) -> list[dict]:
        results = []
        try:
            async for doc in self._collection.aggregate(pipeline):
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
                results.append(doc)
        except Exception as e:
            logger.error("Vector Search pipeline error: %s", e)
            raise
        return results

    async def test_index(self, index_name: str) -> dict:
        """Test Vector Search index by running a dummy query."""
        try:
            pipeline = [
                {
                    "$vectorSearch": {
                        "index": index_name,
                        "path": "embedding",
                        "queryVector": [0.0] * 1024,
                        "numCandidates": 10,
                        "limit": 1,
                    }
                },
                {"$project": {"_id": 1}},
            ]
            results = []
            async for doc in self._collection.aggregate(pipeline):
                results.append(doc)
            return {"status": "ok", "indexName": index_name, "reachable": True}
        except Exception as e:
            return {"status": "error", "indexName": index_name, "reachable": False, "error": str(e)}
