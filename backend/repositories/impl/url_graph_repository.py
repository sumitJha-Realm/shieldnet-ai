"""URL graph repository — edges between related URLs and $graphLookup traversal."""

import logging
from datetime import datetime
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

# Minimum relationship strength to store an edge
EDGE_THRESHOLD = 0.30


class URLGraphRepository:
    """Manages the ``url_edges`` collection.

    Each document represents a directed edge between two scanned URLs.
    Edges are always created bidirectionally so ``$graphLookup`` can
    traverse in any direction.
    """

    def __init__(self, db: AsyncIOMotorDatabase):
        self._edges = db["url_edges"]
        self._urls = db["urls"]

    # ── Index bootstrap (called once at startup) ────────────────────
    async def ensure_indexes(self):
        await self._edges.create_index("fromUrl")
        await self._edges.create_index("toUrl")
        await self._edges.create_index([("fromUrl", 1), ("toUrl", 1)], unique=True)

    # ── Edge CRUD ───────────────────────────────────────────────────
    async def upsert_edge(self, from_url: str, to_url: str,
                          strength: float, factors: list[dict]):
        """Create or update a directed edge."""
        if strength < EDGE_THRESHOLD:
            return
        now = datetime.utcnow()
        await self._edges.update_one(
            {"fromUrl": from_url, "toUrl": to_url},
            {"$set": {
                "strength": round(strength, 3),
                "factors": factors,
                "updatedAt": now,
            }, "$setOnInsert": {"createdAt": now}},
            upsert=True,
        )

    async def upsert_edge_pair(self, url_a: str, url_b: str,
                               strength: float, factors: list[dict]):
        """Create edges in both directions for undirected traversal."""
        await self.upsert_edge(url_a, url_b, strength, factors)
        await self.upsert_edge(url_b, url_a, strength, factors)

    # ── $graphLookup — multi-degree traversal ───────────────────────
    async def get_graph(self, url: str, max_depth: int = 2,
                        min_strength: float = 0.30) -> dict:
        """Return the neighbourhood graph around *url* up to *max_depth* hops.

        Uses ``$graphLookup`` to recursively walk edges, then enriches
        each node with URL metadata from the ``urls`` collection.

        Returns ``{"nodes": [...], "edges": [...]}``.
        """
        pipeline = [
            # Seed: find all edges originating from the scanned URL
            {"$match": {"fromUrl": url, "strength": {"$gte": min_strength}}},
            # Recursive walk
            {"$graphLookup": {
                "from": "url_edges",
                "startWith": "$toUrl",
                "connectFromField": "toUrl",
                "connectToField": "fromUrl",
                "as": "connections",
                "maxDepth": max_depth - 1,   # depth 0 = 1st hop already matched
                "depthField": "degree",
                "restrictSearchWithMatch": {"strength": {"$gte": min_strength}},
            }},
        ]

        raw_results = []
        async for doc in self._edges.aggregate(pipeline):
            raw_results.append(doc)

        # Collect all unique URLs mentioned in the graph
        url_set = {url}  # include the root
        edge_list = []

        for doc in raw_results:
            # The direct edge (degree 1)
            url_set.add(doc["toUrl"])
            edge_list.append({
                "from": doc["fromUrl"],
                "to": doc["toUrl"],
                "strength": doc["strength"],
                "factors": doc.get("factors", []),
                "degree": 1,
            })
            # Recursive connections (degree 2+)
            for conn in doc.get("connections", []):
                url_set.add(conn["fromUrl"])
                url_set.add(conn["toUrl"])
                edge_list.append({
                    "from": conn["fromUrl"],
                    "to": conn["toUrl"],
                    "strength": conn["strength"],
                    "factors": conn.get("factors", []),
                    "degree": int(conn.get("degree", 0)) + 2,
                })

        # De-duplicate edges (keep strongest if duplicated)
        seen_edges = {}
        for e in edge_list:
            key = (e["from"], e["to"])
            if key not in seen_edges or e["strength"] > seen_edges[key]["strength"]:
                seen_edges[key] = e
        unique_edges = list(seen_edges.values())

        # Enrich nodes with URL metadata
        nodes = []
        if url_set:
            cursor = self._urls.find(
                {"url": {"$in": list(url_set)}},
                {"url": 1, "domain": 1, "riskScore": 1, "status": 1,
                 "threatClassification": 1, "submissionDate": 1},
            )
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                doc["isRoot"] = doc["url"] == url
                nodes.append(doc)

            # If root not in DB yet (first scan), add a stub node
            if not any(n.get("isRoot") for n in nodes):
                nodes.append({"url": url, "isRoot": True})

        return {"nodes": nodes, "edges": unique_edges}

    async def get_edge_count(self, url: str) -> int:
        return await self._edges.count_documents({"fromUrl": url})

    async def delete_edges_for_url(self, url: str):
        """Remove all edges involving a URL (both directions)."""
        await self._edges.delete_many({"$or": [{"fromUrl": url}, {"toUrl": url}]})
