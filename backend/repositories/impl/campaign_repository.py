"""Campaign repository — MongoDB operations for threat campaigns."""

import logging
from datetime import datetime
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


class CampaignRepository:
    def __init__(self, db: AsyncIOMotorDatabase, collection_name: str = "campaigns"):
        self._collection = db[collection_name]
        self._urls_collection = db["urls"]

    async def ensure_indexes(self):
        await self._collection.create_index("status")
        await self._collection.create_index("attackCategory")
        await self._collection.create_index("lastSeen", background=True)
        logger.info("Campaign indexes ensured")

    async def insert_one(self, campaign: dict) -> str:
        result = await self._collection.insert_one(campaign)
        return str(result.inserted_id)

    async def find_by_id(self, campaign_id: str) -> Optional[dict]:
        doc = await self._collection.find_one({"_id": ObjectId(campaign_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def find_by_reference(self, campaign_ref: str) -> Optional[dict]:
        """Find a campaign by either Mongo _id or logical campaignId."""
        if not campaign_ref:
            return None

        doc = None
        try:
            if ObjectId.is_valid(campaign_ref):
                doc = await self._collection.find_one({"_id": ObjectId(campaign_ref)})
        except Exception:
            doc = None

        if not doc:
            doc = await self._collection.find_one({"campaignId": campaign_ref})

        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def find_active_campaign(
        self, attack_category: str, time_window_start: datetime
    ) -> Optional[dict]:
        """Find an active campaign matching category within the time window."""
        doc = await self._collection.find_one({
            "attackCategory": attack_category,
            "status": "active",
            "lastSeen": {"$gte": time_window_start},
        }, sort=[("lastSeen", -1)])
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def update_campaign(self, campaign_id: str, update: dict) -> bool:
        result = await self._collection.update_one(
            {"_id": ObjectId(campaign_id)}, {"$set": update}
        )
        return result.modified_count > 0

    async def add_url_to_campaign(
        self, campaign_id: str, url: str, domain: str, risk_score: float
    ) -> bool:
        """Push a URL into the campaign's urls array and update stats."""
        now = datetime.utcnow()
        result = await self._collection.update_one(
            {"_id": ObjectId(campaign_id)},
            {
                "$addToSet": {"urls": url, "domains": domain},
                "$inc": {"urlCount": 1},
                "$set": {"lastSeen": now, "updatedAt": now},
            },
        )
        # Recompute average risk score
        if result.modified_count > 0:
            campaign = await self.find_by_id(campaign_id)
            if campaign:
                url_count = campaign.get("urlCount", 1)
                old_avg = campaign.get("avgRiskScore", 0)
                new_avg = ((old_avg * (url_count - 1)) + risk_score) / url_count
                await self._collection.update_one(
                    {"_id": ObjectId(campaign_id)},
                    {"$set": {"avgRiskScore": round(new_avg, 1)}},
                )
        return result.modified_count > 0

    async def tag_url_with_campaign(self, url: str, campaign_id: str):
        """Set campaignId on the URL document in the urls collection."""
        await self._urls_collection.update_one(
            {"url": url},
            {"$set": {"campaignId": campaign_id}},
        )

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

    async def count(self, filter_doc: dict | None = None) -> int:
        return await self._collection.count_documents(filter_doc or {})
