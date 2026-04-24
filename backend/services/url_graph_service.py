"""Graph service — builds relationship edges after scans and queries the graph."""

import logging
from repositories.impl.url_graph_repository import URLGraphRepository

logger = logging.getLogger(__name__)

# Factor weights used to compute aggregate edge strength
_FACTOR_WEIGHTS = {
    "vector": 0.40,
    "brand": 0.25,
    "hosting": 0.10,
    "tld": 0.10,
    "classification": 0.15,
}


def _compute_edge_strength(factors: list[dict]) -> float:
    """Weighted average of individual factor scores."""
    total = 0.0
    weight_sum = 0.0
    for f in factors:
        w = _FACTOR_WEIGHTS.get(f["type"], 0.05)
        total += w * f["score"]
        weight_sum += w
    return round(total / weight_sum, 3) if weight_sum else 0.0


class URLGraphService:
    def __init__(self, graph_repo: URLGraphRepository):
        self._repo = graph_repo

    async def ensure_indexes(self):
        await self._repo.ensure_indexes()

    # ── Build edges from scan results ───────────────────────────────
    async def build_edges_from_scan(
        self,
        scanned_url: str,
        scanned_record: dict,
        similar_threats: list[dict],
        threat_intel_matches: list[dict],
    ):
        """Called after a URL scan completes.

        Computes relationship factors between the scanned URL and each
        similar URL found during scanning, then persists edges.
        """
        scanned_domain = scanned_record.get("domain", "")
        scanned_classification = scanned_record.get("threatClassification", "benign")
        scanned_tld = scanned_domain.rsplit(".", 1)[-1] if "." in scanned_domain else ""
        scanned_brand = scanned_record.get("brandImpersonation", {})
        scanned_hosting = scanned_record.get("hostingFlags", {})

        edges_created = 0

        for threat in similar_threats:
            threat_url = threat.get("url")
            if not threat_url or threat_url == scanned_url:
                continue

            factors = []
            threat_domain = threat.get("domain", "")

            # Factor 1: Vector similarity (from search score)
            vs = threat.get("score", 0)
            if vs > 0:
                factors.append({"type": "vector", "score": round(vs, 3),
                                "detail": f"{vs:.0%} embedding similarity"})

            # Factor 2: Brand target overlap
            threat_brand = threat.get("brandImpersonation", {})
            if (scanned_brand.get("closest_brand") and
                    scanned_brand.get("closest_brand") == threat_brand.get("closest_brand")):
                brand_score = 1.0 - (abs(
                    (scanned_brand.get("edit_distance") or 99) -
                    (threat_brand.get("edit_distance") or 99)
                ) / 10)
                brand_score = max(0, min(1, brand_score))
                factors.append({"type": "brand", "score": round(brand_score, 3),
                                "detail": f"Both target {scanned_brand['closest_brand']}"})

            # Factor 3: Shared hosting infrastructure
            threat_hosting = threat.get("hostingFlags", {})
            if (threat_hosting.get("hostingProvider") and
                    threat_hosting.get("hostingProvider") == scanned_hosting.get("hostingProvider") and
                    threat_hosting.get("hostingProvider") != "unknown-host-provider"):
                factors.append({"type": "hosting", "score": 0.7,
                                "detail": f"Same host: {scanned_hosting['hostingProvider']}"})

            # Factor 4: Same suspicious TLD
            threat_tld = threat_domain.rsplit(".", 1)[-1] if "." in threat_domain else ""
            if scanned_tld and scanned_tld == threat_tld and scanned_tld in (
                "xyz", "tk", "ml", "ga", "cf", "gq", "top", "buzz", "icu", "cam",
            ):
                factors.append({"type": "tld", "score": 0.6,
                                "detail": f"Shared suspicious TLD .{scanned_tld}"})

            # Factor 5: Same threat classification
            threat_class = threat.get("threatClassification", "")
            if (scanned_classification != "benign" and
                    threat_class == scanned_classification):
                factors.append({"type": "classification", "score": 0.8,
                                "detail": f"Both classified as {scanned_classification}"})

            if not factors:
                continue

            strength = _compute_edge_strength(factors)
            await self._repo.upsert_edge_pair(scanned_url, threat_url, strength, factors)
            edges_created += 1

        logger.info("Built %d edges for %s", edges_created, scanned_url)
        return edges_created

    # ── Query the graph ─────────────────────────────────────────────
    async def get_url_graph(self, url: str, max_depth: int = 2,
                            min_strength: float = 0.30) -> dict:
        return await self._repo.get_graph(url, max_depth, min_strength)
