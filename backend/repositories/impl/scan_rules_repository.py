"""Repository for scan rules — singleton document in MongoDB."""

import copy
import logging
from motor.motor_asyncio import AsyncIOMotorDatabase

from models.scan_rules import DEFAULT_SCAN_RULES

logger = logging.getLogger(__name__)

COLLECTION = "scan_rules"
DOC_ID = "active_rules"


class ScanRulesRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self._col = db[COLLECTION]

    async def get_rules(self) -> dict:
        """Return the active rules document, seeding defaults if absent."""
        doc = await self._col.find_one({"_id": DOC_ID})
        if doc is None:
            doc = copy.deepcopy(DEFAULT_SCAN_RULES)
            await self._col.insert_one(doc)
            logger.info("Seeded default scan rules into MongoDB")
        return doc

    async def update_rules(self, patch: dict) -> dict:
        """Merge *patch* into the active rules document.

        Supports partial updates — only keys present in *patch*
        are overwritten; everything else is preserved.
        """
        # Ensure the document exists first
        await self.get_rules()

        set_doc = {}
        for key, value in patch.items():
            if key == "_id":
                continue
            set_doc[key] = value

        if set_doc:
            await self._col.update_one(
                {"_id": DOC_ID},
                {"$set": set_doc},
            )
            logger.info("Updated scan rules: %s", list(set_doc.keys()))

        return await self.get_rules()

    async def reset_rules(self) -> dict:
        """Reset rules to factory defaults."""
        doc = copy.deepcopy(DEFAULT_SCAN_RULES)
        await self._col.replace_one({"_id": DOC_ID}, doc, upsert=True)
        logger.info("Reset scan rules to defaults")
        return doc
