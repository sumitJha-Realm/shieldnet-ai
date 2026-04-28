"""Campaign detection service — real-time campaign tagging during URL scans.

Detects coordinated attack campaigns by clustering vector search neighbors:
1. Take top-N vector neighbors with similarity >= threshold
2. Group by attackCategory + check temporal proximity
3. If >= MIN_CLUSTER neighbours cluster, create or join an existing campaign
4. Tag the scanned URL with the campaign ID
5. Async background re-embed: bake campaign context into URL embedding so
   future vector searches naturally cluster campaign members closer (single
   query — no second vector search needed)
"""

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

from repositories.impl.campaign_repository import CampaignRepository

logger = logging.getLogger(__name__)

# ── Tunables ────────────────────────────────────────────────────────
MIN_SIMILARITY = 0.78           # only consider neighbours above this
MIN_CLUSTER_SIZE = 2            # minimum neighbours to form a cluster
CAMPAIGN_TIME_WINDOW_HOURS = 72 # how far back to look for active campaigns
SEVERITY_MAP = {
    "phishing": "critical",
    "malware": "critical",
    "c2": "high",
    "suspicious": "medium",
    "benign": "low",
}


class CampaignDetectionService:
    def __init__(self, campaign_repo: CampaignRepository):
        self._repo = campaign_repo

    async def get_campaign(self, campaign_ref: str) -> Optional[dict]:
        """Fetch campaign details by either _id or logical campaignId."""
        return await self._repo.find_by_reference(campaign_ref)

    # ── Public: detect + tag ─────────────────────────────────────────

    async def detect_and_tag(
        self,
        scanned_url: str,
        scanned_domain: str,
        scanned_risk: float,
        scanned_classification: str,
        similar_threats: list[dict],
        threat_intel_matches: list[dict],
        atlas_signals: dict | None = None,
        url_record: dict = None,
    ) -> Optional[dict]:
        """Analyse vector neighbours and tag into a campaign if cluster found.

        Neighbor consensus check first (no extra query).
        Falls back to indexed category lookup.
        Falls back to create new campaign.
        Schedules background re-embed to bake campaign context into URL vector.
        """
        # 1. Merge and filter neighbours by similarity
        all_neighbours = [
            n for n in (similar_threats + threat_intel_matches)
            if n.get("score", 0) >= MIN_SIMILARITY
        ]
        if len(all_neighbours) < MIN_CLUSTER_SIZE:
            return None

        # 2. Neighbor consensus: if neighbors already share a campaign, join it
        campaign_votes = Counter(
            n.get("campaignId") for n in all_neighbours if n.get("campaignId")
        )
        atlas_max_score = (atlas_signals or {}).get("maxSearchScore", 0.0)
        atlas_categories = set((atlas_signals or {}).get("matchedAttackCategories", []))
        if campaign_votes:
            best_id, vote_count = campaign_votes.most_common(1)[0]
            if vote_count >= 2 or (vote_count == 1 and atlas_max_score >= 6.5):
                await self._repo.add_url_to_campaign(
                    best_id, scanned_url, scanned_domain, scanned_risk
                )
                await self._repo.tag_url_with_campaign(scanned_url, best_id)
                campaign = await self._repo.find_by_id(best_id)
                if vote_count == 1 and atlas_categories and campaign:
                    if campaign.get("attackCategory") not in atlas_categories:
                        campaign = None
                if not campaign:
                    # fall through to cluster/category path if lexical evidence disagrees
                    pass
                else:
                    logger.info("URL %s joined existing campaign %s via consensus", scanned_url, best_id)
                    return campaign

        # 3. Group by attack category + find best cluster
        best_category, best_cluster = self._find_best_cluster(all_neighbours)
        if not best_category and atlas_categories and atlas_max_score >= 7.0:
            # lexical-only fallback when vector cluster is sparse
            best_category = next(iter(atlas_categories))
            best_cluster = []
        if not best_category:
            return None

        # 4. Indexed lookup for recent active campaign
        time_window_start = datetime.utcnow() - timedelta(hours=CAMPAIGN_TIME_WINDOW_HOURS)
        existing = await self._repo.find_active_campaign(best_category, time_window_start)

        if existing:
            campaign_id = existing["_id"]
            await self._repo.add_url_to_campaign(
                campaign_id, scanned_url, scanned_domain, scanned_risk
            )
            await self._repo.tag_url_with_campaign(scanned_url, campaign_id)
            campaign = await self._repo.find_by_id(campaign_id)
            logger.info("URL %s added to existing campaign %s (%s)", scanned_url, campaign_id, best_category)
            return campaign

        # 5. Create new campaign
        domains = list({n.get("domain", "") for n in best_cluster if n.get("domain")})
        tlds = list({(n.get("domain") or "").rsplit(".", 1)[-1] for n in best_cluster})
        avg_sim = sum(n.get("score", 0) for n in best_cluster) / len(best_cluster)
        now = datetime.utcnow()

        campaign_doc = {
            "name": f"{best_category.replace('_', ' ').title()} Campaign — {now.strftime('%d %b %Y %H:%M')}",
            "attackCategory": best_category,
            "severity": SEVERITY_MAP.get(scanned_classification, "medium"),
            "status": "active",
            "urls": [scanned_url] + [n.get("url", "") for n in best_cluster if n.get("url")],
            "domains": list({scanned_domain} | set(domains)),
            "urlCount": 1 + len(best_cluster),
            "avgRiskScore": round(
                (scanned_risk + sum(n.get("riskScore", 0) for n in best_cluster))
                / (1 + len(best_cluster)), 1,
            ),
            "avgSimilarity": round(avg_sim, 3),
            "sharedTlds": tlds,
            "clusterSize": len(best_cluster),
            "firstSeen": now,
            "lastSeen": now,
            "createdAt": now,
            "updatedAt": now,
        }
        campaign_id = await self._repo.insert_one(campaign_doc)
        campaign_doc["_id"] = campaign_id

        # Tag all URLs in the cluster
        await self._repo.tag_url_with_campaign(scanned_url, campaign_id)
        for n in best_cluster:
            if n.get("url"):
                await self._repo.tag_url_with_campaign(n["url"], campaign_id)

        logger.info(
            "New campaign created: %s (id=%s, %d URLs, category=%s)",
            campaign_doc["name"], campaign_id, campaign_doc["urlCount"], best_category,
        )
        return campaign_doc

    # ── Private helpers ──────────────────────────────────────────────

    def _find_best_cluster(self, neighbours: list[dict]) -> tuple[Optional[str], list[dict]]:
        """Group by attack category, return largest cluster that meets threshold."""
        category_groups: dict[str, list[dict]] = {}
        for n in neighbours:
            cat = (
                n.get("attackCategory")
                or n.get("threatClassification")
                or "unknown"
            )
            category_groups.setdefault(cat, []).append(n)

        best_category = None
        best_cluster: list[dict] = []
        for cat, members in category_groups.items():
            if cat in ("benign", "unknown"):
                continue
            if len(members) >= MIN_CLUSTER_SIZE and len(members) > len(best_cluster):
                best_category = cat
                best_cluster = members

        return best_category, best_cluster

    async def _reembed_url_with_campaign(
        self,
        url: str,
        url_record: dict,
        campaign: dict,
    ) -> None:
        """Background task: re-embed URL with campaign context baked in.

        This makes future $vectorSearch naturally cluster campaign members
        together with higher cosine similarity — no second query needed.
        """
        try:
            enriched_summary = build_campaign_enriched_summary(
                url=url,
                features={
                    "domain": url_record.get("domain", ""),
                    "hostingFlags": url_record.get("hostingFlags", {
                        "domainAgeDays": 0, "sslValid": False,
                        "isSharedHosting": False, "hostingProvider": "unknown",
                        "geoLocation": "unknown",
                    }),
                    "urlStructure": url_record.get("urlStructure", {
                        "pathDepth": 0, "entropyScore": 0.0,
                        "hasIpAddress": False, "hasSuspiciousTld": False,
                        "containsEncodedChars": False, "subdomainCount": 0,
                    }),
                    "dnsStatus": url_record.get("dnsStatus", "active"),
                    "dgaAnalysis": url_record.get("dgaAnalysis"),
                    "homoglyphAnalysis": url_record.get("homoglyphAnalysis"),
                    "tldRisk": url_record.get("tldRisk"),
                    "structuralAnalysis": url_record.get("structuralAnalysis"),
                    "semanticFeatures": url_record.get("semanticFeatures"),
                    "brandImpersonation": url_record.get("brandImpersonation"),
                    "payloadTypes": url_record.get("payloadTypes", []),
                    "queryParams": url_record.get("queryParams", {}),
                },
                campaign=campaign,
                classification=url_record.get("threatClassification", ""),
                risk_score=url_record.get("riskScore", 0.0),
                status=url_record.get("status", ""),
                scan_count=url_record.get("scanCount", 1),
            )
            new_embedding = await get_embedding(enriched_summary)

            await self._repo._urls_collection.update_one(
                {"url": url},
                {
                    "$set": {
                        "summaryText": enriched_summary,
                        "embedding": new_embedding,
                        "campaignId": str(campaign["_id"]),
                        "campaignName": campaign.get("name"),
                    }
                },
            )
            logger.info("Re-embedded URL with campaign context: %s", url)
        except Exception as e:
            logger.warning("Background re-embed failed for %s: %s", url, e)
        """Analyse vector neighbours and tag into a campaign if cluster found.

        Returns the campaign dict if tagged, else None.
        """
        # 1. Merge and filter neighbours by similarity
        all_neighbours = [
            n for n in (similar_threats + threat_intel_matches)
            if n.get("score", 0) >= MIN_SIMILARITY
        ]
        if len(all_neighbours) < MIN_CLUSTER_SIZE:
            return None

        # 2. Group by attack category (use threatClassification as fallback)
        category_groups: dict[str, list[dict]] = {}
        for n in all_neighbours:
            cat = (
                n.get("attackCategory")
                or n.get("threatClassification")
                or "unknown"
            )
            category_groups.setdefault(cat, []).append(n)

        # 3. Find the largest cluster that meets threshold
        best_category = None
        best_cluster = []
        for cat, members in category_groups.items():
            if cat in ("benign", "unknown"):
                continue
            if len(members) >= MIN_CLUSTER_SIZE and len(members) > len(best_cluster):
                best_category = cat
                best_cluster = members

        if not best_category:
            return None

        # 4. Check temporal proximity — members should have been seen
        #    within the campaign time window
        time_window_start = datetime.utcnow() - timedelta(hours=CAMPAIGN_TIME_WINDOW_HOURS)

        # 5. Find or create campaign
        existing = await self._repo.find_active_campaign(
            best_category, time_window_start
        )

        # Collect shared traits for campaign metadata
        domains = list({n.get("domain", "") for n in best_cluster if n.get("domain")})
        tlds = list({(n.get("domain") or "").rsplit(".", 1)[-1] for n in best_cluster})
        avg_sim = sum(n.get("score", 0) for n in best_cluster) / len(best_cluster)

        if existing:
            campaign_id = existing["_id"]
            await self._repo.add_url_to_campaign(
                campaign_id, scanned_url, scanned_domain, scanned_risk
            )
            await self._repo.tag_url_with_campaign(scanned_url, campaign_id)
            campaign = await self._repo.find_by_id(campaign_id)
            logger.info(
                "URL %s added to existing campaign %s (%s)",
                scanned_url, campaign_id, best_category,
            )
            return campaign
        else:
            # Create new campaign
            now = datetime.utcnow()
            campaign_doc = {
                "name": f"{best_category.replace('_', ' ').title()} Campaign — {now.strftime('%d %b %Y %H:%M')}",
                "attackCategory": best_category,
                "severity": SEVERITY_MAP.get(scanned_classification, "medium"),
                "status": "active",
                "urls": [scanned_url] + [n.get("url", "") for n in best_cluster if n.get("url")],
                "domains": list({scanned_domain} | set(domains)),
                "urlCount": 1 + len(best_cluster),
                "avgRiskScore": round(
                    (scanned_risk + sum(n.get("riskScore", 0) for n in best_cluster))
                    / (1 + len(best_cluster)),
                    1,
                ),
                "avgSimilarity": round(avg_sim, 3),
                "sharedTlds": tlds,
                "clusterSize": len(best_cluster),
                "firstSeen": now,
                "lastSeen": now,
                "createdAt": now,
                "updatedAt": now,
            }
            campaign_id = await self._repo.insert_one(campaign_doc)
            campaign_doc["_id"] = campaign_id

            # Tag all URLs in the cluster
            await self._repo.tag_url_with_campaign(scanned_url, campaign_id)
            for n in best_cluster:
                if n.get("url"):
                    await self._repo.tag_url_with_campaign(n["url"], campaign_id)

            logger.info(
                "New campaign created: %s (id=%s, %d URLs, category=%s)",
                campaign_doc["name"], campaign_id,
                campaign_doc["urlCount"], best_category,
            )
            return campaign_doc
