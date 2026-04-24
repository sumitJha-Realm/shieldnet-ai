"""URL analysis service — core scanning logic."""

import logging
import time
from datetime import datetime
from typing import Optional

from repositories.impl.url_repository import URLRepository
from repositories.impl.threat_intel_repository import ThreatIntelRepository
from services.embedding_service import get_embedding
from services.search.vector_search_service import VectorSearchService
from services.waterfall_cache import WaterfallCache
from utils.url_feature_extractor import (
    extract_features,
    enrich_features,
    build_summary_text,
    calculate_risk_score,
    classify_threat,
    risk_level,
    recommended_action,
)

logger = logging.getLogger(__name__)


class URLAnalysisService:
    def __init__(
        self,
        url_repo: URLRepository,
        vector_search_service: "VectorSearchService",
        threat_intel_repo: Optional["ThreatIntelRepository"] = None,
        cache: Optional["WaterfallCache"] = None,
    ):
        self._url_repo = url_repo
        self._vector_search = vector_search_service
        self._threat_intel_repo = threat_intel_repo
        self._cache = cache or WaterfallCache()

    async def scan_url(self, url: str) -> dict:
        """Full URL scanning pipeline with waterfall enforcement.

        Tier 1 — L1 cache (< 1ms): Check in-memory LRU for recent result
        Tier 2 — L2 MongoDB (< 10ms): Exact URL lookup in urls collection
        Tier 3 — L3 full pipeline: Feature extraction → Embedding → Vector search
        """
        start = time.monotonic()
        logger.info("Scanning URL: %s", url)

        # ── L1: In-memory cache check ────────────────────────────────────
        cached = self._cache.get(url)
        if cached:
            elapsed = (time.monotonic() - start) * 1000
            cached["waterfallTier"] = "L1_CACHE"
            cached["latencyMs"] = round(elapsed, 2)
            logger.info("L1 cache hit for %s (%.2fms)", url, elapsed)
            return cached

        # ── L2: MongoDB exact-URL lookup ─────────────────────────────────
        existing = await self._url_repo.find_by_url(url)
        if existing and existing.get("embedding"):
            elapsed = (time.monotonic() - start) * 1000
            logger.info("L2 DB hit for %s (%.2fms)", url, elapsed)
            # Re-run vector search with stored embedding for fresh intel
            result = await self._run_full_analysis(
                url, existing_record=existing, existing_embedding=existing["embedding"],
            )
            result["waterfallTier"] = "L2_DATABASE"
            result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
            self._cache.put(url, result)
            return result

        # ── L3: Full analysis pipeline ───────────────────────────────────
        result = await self._run_full_analysis(url)
        result["waterfallTier"] = "L3_FULL_PIPELINE"
        result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
        self._cache.put(url, result)
        logger.info("L3 full pipeline for %s (%.2fms)", url, result["latencyMs"])
        return result

    async def _run_full_analysis(
        self, url: str,
        existing_record: dict = None,
        existing_embedding: list = None,
    ) -> dict:
        """Run the complete analysis pipeline."""

        # 1. Feature extraction + advanced enrichment
        features = extract_features(url)
        features = enrich_features(url, features)

        # 2. Build summary text (now includes DGA, homoglyph, structural signals)
        summary_text = build_summary_text(url, features)

        # 3. Generate embedding (or reuse existing)
        embedding = existing_embedding
        if not embedding:
            try:
                embedding = await get_embedding(summary_text)
            except Exception as e:
                logger.warning("Embedding generation failed: %s — proceeding without", e)
                embedding = None

        # 4. Vector search for similar threats (from urls collection)
        similar_threats = []
        max_similarity = 0.0
        if embedding:
            try:
                similar_threats = await self._vector_search.search_similar(
                    query_vector=embedding, limit=5
                )
                if similar_threats:
                    max_similarity = similar_threats[0].get("score", 0.0)
            except Exception as e:
                logger.warning("Vector search failed: %s", e)

        # 4b. Cross-reference against threat intel feeds
        threat_intel_matches = []
        max_intel_similarity = 0.0
        scanned_domain = features["domain"].lower()
        if embedding and self._threat_intel_repo:
            try:
                raw_matches = await self._threat_intel_repo.vector_search(
                    query_vector=embedding, limit=10
                )
                # Filter: drop matches where the threat entry targets/abuses the
                # SAME base domain as the scanned URL.  These entries describe
                # attacks *against* the legitimate domain, not evidence that the
                # scanned URL itself is malicious.
                for m in raw_matches:
                    threat_url = (m.get("url") or "").lower()
                    threat_desc = (m.get("description") or "").lower()
                    # Same base domain in the threat entry URL → victim, not attacker
                    if scanned_domain in threat_url:
                        # Only keep if the threat URL is exactly the scanned URL
                        parsed_scanned = url.lower().rstrip("/")
                        parsed_threat = threat_url.rstrip("/")
                        if parsed_threat != parsed_scanned:
                            continue
                    # Description mentions "legitimate domain" + our domain → victim context
                    if "legitimate domain" in threat_desc and scanned_domain in threat_desc:
                        continue
                    threat_intel_matches.append(m)
                    if len(threat_intel_matches) >= 5:
                        break
                if threat_intel_matches:
                    max_intel_similarity = threat_intel_matches[0].get("score", 0.0)
            except Exception as e:
                logger.warning("Threat intel search failed: %s", e)

        # 5. Risk scoring (use best similarity from either source)
        best_similarity = max(max_similarity, max_intel_similarity)
        risk = calculate_risk_score(features, best_similarity, url=url)
        classification = classify_threat(risk)

        # 6. Build record
        now = datetime.utcnow()
        record = {
            "url": url,
            "domain": features["domain"],
            "submissionDate": now,
            "source": "gov_employee_report",
            "dnsStatus": features["dnsStatus"],
            "hostingFlags": features["hostingFlags"],
            "urlStructure": features["urlStructure"],
            "dgaAnalysis": features.get("dgaAnalysis"),
            "homoglyphAnalysis": features.get("homoglyphAnalysis"),
            "tldRisk": features.get("tldRisk"),
            "structuralAnalysis": features.get("structuralAnalysis"),
            "semanticFeatures": features.get("semanticFeatures"),
            "brandImpersonation": features.get("brandImpersonation"),
            "threatClassification": classification,
            "riskScore": risk,
            "status": "blocked" if risk >= 75 else ("under_review" if risk >= 50 else "allowed"),
            "reviewedBy": "system_ai",
            "summaryText": summary_text,
            "embedding": embedding,
            "createdAt": now,
            "updatedAt": now,
        }

        # 7. Persist (upsert — update if URL already exists)
        if existing_record:
            doc_id = existing_record["_id"]
            await self._url_repo.update_one(doc_id, {
                k: v for k, v in record.items() if k != "_id"
            })
            record["_id"] = doc_id
        else:
            existing = await self._url_repo.find_by_url(url)
            if existing:
                doc_id = existing["_id"]
                await self._url_repo.update_one(doc_id, {
                    k: v for k, v in record.items() if k != "_id"
                })
                record["_id"] = doc_id
            else:
                doc_id = await self._url_repo.insert_one(record)
                record["_id"] = doc_id

        return {
            "urlRecord": record,
            "similarThreats": similar_threats,
            "threatIntelMatches": threat_intel_matches,
            "recommendedAction": recommended_action(risk),
            "riskLevel": risk_level(risk),
            "analysisSummary": self._build_analysis_summary(
                url, features, classification, risk, record["status"],
                similar_threats, threat_intel_matches,
                max_similarity, max_intel_similarity,
            ),
        }

    def _build_analysis_summary(
        self, url, features, classification, risk, status,
        similar_threats, threat_intel_matches,
        max_similarity, max_intel_similarity,
    ) -> dict:
        """Build a human-readable analysis summary with full explainability.

        When the Vector DB blocks a URL because it is 'mathematically close'
        to a threat, we translate that into concrete, human-readable reasons.
        """
        reasons = []
        domain = features["domain"]
        hf = features["hostingFlags"]
        us = features["urlStructure"]

        # ── DGA detection reasons ────────────────────────────────────────
        dga = features.get("dgaAnalysis")
        if dga and dga.get("isDGA"):
            reasons.append(
                f"⚙️ DGA DETECTED (score: {dga['dgaScore']:.0%}) — This domain appears to be "
                "algorithmically generated (similar to Suppobox/Mirai patterns). "
                "DGA domains are created by malware to evade static blacklists."
            )
            for sig in dga.get("dgaSignals", [])[:2]:
                reasons.append(f"  ↳ {sig}")

        # ── Homoglyph / typosquat reasons ────────────────────────────────
        homoglyph = features.get("homoglyphAnalysis")
        if homoglyph and homoglyph.get("hasHomoglyphs"):
            target = homoglyph.get("targetDomain", "a government portal")
            reasons.append(
                f"👁️ VISUAL IMPERSONATION — This domain uses characters that "
                f"visually mimic '{target}'. Attackers use look-alike characters "
                "(Cyrillic, digit/letter swaps) to trick users."
            )
            for sig in homoglyph.get("homoglyphSignals", [])[:2]:
                reasons.append(f"  ↳ {sig}")

        # ── Brand impersonation / typosquatting reasons ────────────────
        brand = features.get("brandImpersonation")
        if brand and not brand.get("is_exact_match") and 0 < brand.get("edit_distance", 999) <= 3:
            reasons.append(
                f"🏛️ BRAND IMPERSONATION — Domain is {brand['edit_distance']} character(s) away from "
                f"known government domain '{brand['known_domain']}' ({brand['closest_brand']}). "
                "Typosquatting domains mimic trusted sites to steal credentials."
            )

        # ── Phishing keyword reasons ─────────────────────────────────────
        _PHISHING_KW = {
            "login", "signin", "verify", "secure", "account", "update",
            "confirm", "banking", "password", "credential", "auth",
            "portal", "validate", "suspend", "unlock", "otp", "kyc",
        }
        url_lower = url.lower()
        kw_found = [kw for kw in _PHISHING_KW if kw in url_lower]
        if kw_found:
            reasons.append(
                f"🎣 PHISHING KEYWORDS — URL contains {len(kw_found)} social engineering "
                f"keyword(s): {', '.join(kw_found)}. These terms are used to create urgency "
                "and trick users into submitting credentials."
            )

        # ── Structural / bypass technique reasons ────────────────────────
        structural = features.get("structuralAnalysis")
        if structural and structural.get("bypassTechniques"):
            techniques = structural["bypassTechniques"]
            bypass_names = {
                "path_traversal": "Path Traversal (../)",
                "encoding_obfuscation": "URL Encoding Obfuscation",
                "base64_payload": "Base64 Encoded Payload",
                "open_redirect": "Open Redirect Exploitation",
                "command_injection": "Command Injection",
                "xss_payload": "Cross-Site Scripting (XSS)",
                "sql_injection": "SQL Injection",
                "dns_tunneling": "DNS Tunneling / C2 Beaconing",
                "dns_exfiltration": "DNS Data Exfiltration",
            }
            names = [bypass_names.get(t, t) for t in techniques]
            reasons.append(
                f"🛡️ BYPASS TECHNIQUES ({len(techniques)}) — "
                f"Detected: {', '.join(names)}. These techniques would "
                "evade standard regex/rule-based filters."
            )
            for sig in structural.get("structuralSignals", [])[:3]:
                reasons.append(f"  ↳ {sig}")

        # ── Domain-level risks ───────────────────────────────────────────
        if hf["domainAgeDays"] < 30:
            reasons.append(f"Domain is only {hf['domainAgeDays']} days old — newly registered domains are commonly used in attacks")
        elif hf["domainAgeDays"] < 180:
            reasons.append(f"Domain is {hf['domainAgeDays']} days old — relatively new domain")

        if not hf["sslValid"]:
            reasons.append("No valid SSL certificate — legitimate government sites always use HTTPS with valid certificates")

        tld_risk = features.get("tldRisk")
        if tld_risk and tld_risk.get("tldRisk") == "high":
            reasons.append(f"Uses high-risk TLD (.{domain.split('.')[-1]}) — {tld_risk.get('tldNote', 'frequently abused')}")
        elif us.get("hasSuspiciousTld"):
            reasons.append(f"Uses suspicious TLD (.{domain.split('.')[-1]}) — commonly associated with malicious domains")

        if us.get("hasIpAddress"):
            reasons.append("Domain contains an IP address instead of a hostname — typical of phishing/C2 infrastructure")

        if us.get("entropyScore", 0) > 4.5:
            reasons.append(f"High URL entropy ({us['entropyScore']:.2f}) — randomized characters suggest auto-generated malicious URL")

        if us.get("containsEncodedChars"):
            reasons.append("Contains encoded characters — may be attempting to obfuscate malicious payload")

        if features["dnsStatus"] in ("suspended", "parked"):
            reasons.append(f"DNS status is '{features['dnsStatus']}' — domain is not actively serving legitimate content")

        if hf.get("isSharedHosting"):
            reasons.append("Hosted on shared infrastructure — common for low-cost malicious hosting")

        # ── Vector search explainability ─────────────────────────────────
        blocked_similar = [t for t in similar_threats if t.get("status") == "blocked"]
        malicious_similar = [t for t in similar_threats if t.get("threatClassification") in ("phishing", "malware", "c2")]
        if blocked_similar:
            reasons.append(
                f"🔗 VECTOR MATCH — Matches {len(blocked_similar)} previously blocked URL(s) "
                f"with up to {max_similarity * 100:.0f}% cosine similarity in the embedding space. "
                "This means the URL's structural DNA closely resembles known threats."
            )
        elif malicious_similar:
            reasons.append(
                f"🔗 SEMANTIC PROXIMITY — Semantically similar to {len(malicious_similar)} known threat(s) "
                f"({max_similarity * 100:.0f}% similarity). The URL's features cluster near known malicious URLs "
                "in vector space even though it may not appear on any blacklist."
            )

        # ── Threat intel explainability ──────────────────────────────────
        # Only surface threat intel matches at ≥85% similarity to avoid
        # false-positive noise from generic domain-family matches.
        high_conf_intel = [t for t in threat_intel_matches if t.get("score", 0) >= 0.85]
        if high_conf_intel:
            feeds = list(set(t.get("feedName", "Unknown") for t in high_conf_intel[:3]))
            types = list(set(t.get("threatType", "unknown") for t in high_conf_intel))
            top_score = high_conf_intel[0].get("score", 0)
            reasons.append(
                f"📡 THREAT INTEL — Similar to {len(high_conf_intel)} "
                f"{'/'.join(types)} pattern(s) reported by {', '.join(feeds)} "
                f"at up to {top_score * 100:.0f}% vector similarity."
            )

        # ── Verdict ──────────────────────────────────────────────────────
        if status == "blocked":
            verdict = (
                f"This URL has been automatically BLOCKED. It is classified as "
                f"'{classification}' with a risk score of {risk}/100. "
                f"The Hybrid Enforcement Engine identified {len(reasons)} risk indicators."
            )
        elif status == "under_review":
            verdict = (
                f"This URL is flagged for MANUAL REVIEW. It is classified as "
                f"'{classification}' with a risk score of {risk}/100. "
                f"The system detected {len(reasons)} warning signals that require human judgment."
            )
        else:
            verdict = (
                f"This URL appears SAFE. It is classified as '{classification}' "
                f"with a risk score of {risk}/100."
            )

        # ── Semantic feature summary ─────────────────────────────────────
        semantic = features.get("semanticFeatures", {})

        return {
            "verdict": verdict,
            "classification": classification,
            "status": status,
            "reasons": reasons,
            "semanticFeatures": {
                "visualSimilarity": semantic.get("visualSimilarity", 0),
                "tldEntropy": semantic.get("tldEntropy", 0),
                "consonantRatio": semantic.get("consonantRatio", 0),
                "domainTokenization": semantic.get("domainTokenization", 0),
                "asnReputation": semantic.get("asnReputation", 0),
                "dgaScore": semantic.get("dgaScore", 0),
                "bigramLegitimacy": semantic.get("bigramLegitimacy", 0),
            },
            "riskFactors": {
                "domainAge": hf["domainAgeDays"],
                "sslValid": hf["sslValid"],
                "entropy": us.get("entropyScore", 0),
                "dnsStatus": features["dnsStatus"],
                "vectorSimilarity": round(max(max_similarity, max_intel_similarity) * 100, 1),
                "threatIntelHits": len(threat_intel_matches),
                "blockedSimilar": len(blocked_similar),
                "dgaDetected": bool(dga and dga.get("isDGA")),
                "homoglyphDetected": bool(homoglyph and homoglyph.get("hasHomoglyphs")),
                "brandImpersonation": bool(brand and not brand.get("is_exact_match") and 0 < brand.get("edit_distance", 999) <= 3),
                "bypassTechniques": structural.get("bypassTechniques", []) if structural else [],
            },
        }

    async def get_url(self, url_id: str) -> Optional[dict]:
        return await self._url_repo.find_by_id(url_id)

    async def list_urls(
        self, skip: int = 0, limit: int = 20, status: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> dict:
        filter_doc: dict = {}
        if status:
            filter_doc["status"] = status
        if classification:
            filter_doc["threatClassification"] = classification
        urls = await self._url_repo.find_many(
            filter_doc=filter_doc, skip=skip, limit=limit,
            sort=[("createdAt", -1)],
        )
        total = await self._url_repo.count(filter_doc)
        return {"urls": urls, "total": total, "skip": skip, "limit": limit}

    async def update_status(self, url_id: str, status: str) -> bool:
        # Invalidate cache for this URL on status change
        url_doc = await self._url_repo.find_by_id(url_id)
        if url_doc:
            self._cache.invalidate(url_doc.get("url", ""))
        return await self._url_repo.update_one(
            url_id, {"status": status, "updatedAt": datetime.utcnow()}
        )

    def get_cache_stats(self) -> dict:
        """Return waterfall cache statistics."""
        return self._cache.stats

    async def get_dashboard_stats(self) -> dict:
        total = await self._url_repo.count()
        blocked_today_pipeline = [
            {
                "$match": {
                    "status": "blocked",
                    "createdAt": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)},
                }
            },
            {"$count": "count"},
        ]
        blocked_today_res = await self._url_repo.aggregate(blocked_today_pipeline)
        blocked_today = blocked_today_res[0]["count"] if blocked_today_res else 0

        under_review = await self._url_repo.count({"status": "under_review"})
        active_threats = await self._url_repo.count(
            {"threatClassification": {"$in": ["phishing", "malware", "c2"]}}
        )

        risk_pipeline = [
            {"$group": {"_id": "$threatClassification", "count": {"$sum": 1}}}
        ]
        risk_dist = await self._url_repo.aggregate(risk_pipeline)
        risk_distribution = {item["_id"]: item["count"] for item in risk_dist}

        return {
            "totalScanned": total,
            "blockedToday": blocked_today,
            "underReview": under_review,
            "activeThreats": active_threats,
            "riskDistribution": risk_distribution,
        }

    async def get_threat_trends(self, days: int = 30) -> list[dict]:
        from datetime import timedelta

        start_date = datetime.utcnow() - timedelta(days=days)
        pipeline = [
            {"$match": {"createdAt": {"$gte": start_date}}},
            {
                "$group": {
                    "_id": {
                        "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$createdAt"}},
                        "classification": "$threatClassification",
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id.date": 1}},
        ]
        return await self._url_repo.aggregate(pipeline)
