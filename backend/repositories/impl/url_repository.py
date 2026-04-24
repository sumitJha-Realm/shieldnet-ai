"""Concrete MongoDB URL repository implementation."""

import logging
from typing import Optional
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from repositories.interfaces import URLRepositoryInterface

logger = logging.getLogger(__name__)


class URLRepository(URLRepositoryInterface):
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str = "urls"):
        self._collection = db[collection_name]

    async def insert_one(self, document: dict) -> str:
        result = await self._collection.insert_one(document)
        return str(result.inserted_id)

    async def find_by_url(self, url: str) -> Optional[dict]:
        doc = await self._collection.find_one({"url": url})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def find_by_id(self, doc_id: str) -> Optional[dict]:
        doc = await self._collection.find_one({"_id": ObjectId(doc_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def find_many(
        self,
        filter_doc: dict | None = None,
        skip: int = 0,
        limit: int = 20,
        sort: list[tuple] | None = None,
    ) -> list[dict]:
        cursor = self._collection.find(filter_doc or {})
        if sort:
            cursor = cursor.sort(sort)
        cursor = cursor.skip(skip).limit(limit)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    async def update_one(self, doc_id: str, update: dict) -> bool:
        result = await self._collection.update_one(
            {"_id": ObjectId(doc_id)}, {"$set": update}
        )
        return result.modified_count > 0

    async def count(self, filter_doc: dict | None = None) -> int:
        return await self._collection.count_documents(filter_doc or {})

    async def aggregate(self, pipeline: list[dict]) -> list[dict]:
        results = []
        async for doc in self._collection.aggregate(pipeline):
            if "_id" in doc and isinstance(doc["_id"], ObjectId):
                doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
