"""URL analysis service — core scanning logic with multi-collection support (25 UCs)."""

import asyncio
import hashlib
import logging
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from repositories.impl.url_repository import URLRepository
from repositories.impl.scan_rules_repository import ScanRulesRepository
from repositories.impl.multi_collection_repository import MultiCollectionRepository
from services.embedding_service import get_embedding, get_multilingual_embedding, get_visual_embedding
from services.search.atlas_search_service import AtlasSearchService
from services.search.vector_search_service import VectorSearchService
from services.waterfall_cache import WaterfallCache
from services.url_graph_service import URLGraphService
from services.campaign_detection_service import CampaignDetectionService
from utils.url_feature_extractor import (
    extract_features,
    enrich_features,
    build_summary_text,
    build_campaign_enriched_summary,
    build_scan_signals,
    build_regional_text,
    build_visual_description,
    find_phishing_keyword_matches,
    calculate_risk_score,
    classify_threat,
    risk_level,
    recommended_action,
    detect_payload_types,
    classify_payload_severity,
    derive_payload_signature,
)

logger = logging.getLogger(__name__)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly",
    "shorturl.at", "cutt.ly", "rb.gy", "ow.ly",
}


class URLAnalysisService:
    def __init__(
        self,
        url_repo: URLRepository,
        vector_search_service: "VectorSearchService",
        atlas_search_service: Optional["AtlasSearchService"] = None,
        multi_collection_repo: Optional["MultiCollectionRepository"] = None,
        cache: Optional["WaterfallCache"] = None,
        rules_repo: Optional["ScanRulesRepository"] = None,
        graph_service: Optional["URLGraphService"] = None,
        campaign_service: Optional["CampaignDetectionService"] = None,
    ):
        self._url_repo = url_repo
        self._vector_search = vector_search_service
        self._atlas_search = atlas_search_service
        self._multi = multi_collection_repo
        self._cache = cache or WaterfallCache()
        self._rules_repo = rules_repo
        self._graph_service = graph_service
        self._campaign_service = campaign_service

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            parsed = urlparse(f"http://{url}")
        return (parsed.hostname or parsed.netloc or url or "").strip().lower().rstrip(".")

    @staticmethod
    def _canonical_domain(domain: str) -> str:
        d = (domain or "").strip().lower().rstrip(".")
        if d.startswith("www.") and d.count(".") >= 2:
            return d[4:]
        return d

    @staticmethod
    def _normalize_page_content(page_content: str) -> str:
        return " ".join((page_content or "").split())

    @classmethod
    def _build_cache_key(cls, url: str, page_content: str) -> str:
        normalized = cls._normalize_page_content(page_content)
        if not normalized:
            return url
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
        return f"{url}#pc:{digest}"

    @staticmethod
    def _append_page_content(summary_text: str, page_content: str) -> str:
        normalized = " ".join((page_content or "").split())
        if not normalized:
            return summary_text
        return f"{summary_text}, page content snippet {normalized[:1000]}"

    @staticmethod
    def _intel_feed_name(doc: dict) -> str:
        feed_metadata = doc.get("feedMetadata", {})
        return (
            doc.get("feedName")
            or feed_metadata.get("feedName")
            or doc.get("source")
            or doc.get("_sourceCollection")
            or "Unknown"
        )

    @staticmethod
    def _intel_pattern_type(doc: dict) -> str:
        return (
            doc.get("threatClassification")
            or doc.get("threatType")
            or doc.get("attackCategory")
            or doc.get("anomalyType")
            or doc.get("_sourceCollection")
            or "unknown"
        )

    @classmethod
    def _refine_classification(
        cls,
        classification: str,
        risk: float,
        thresholds: dict,
        features: dict,
        threat_intel_matches: list[dict],
        page_content: str,
    ) -> str:
        if classification in {"phishing", "c2"}:
            return classification

        review_score = thresholds.get("reviewScore", 50)
        if risk < review_score:
            return classification

        phishing_keywords = thresholds.get("phishingKeywords") or [
            "login", "verify", "update", "account", "otp", "secure",
            "kyc", "link", "refund", "claim", "aadhaar", "pan",
        ]
        keyword_matches = find_phishing_keyword_matches(
            f"{features.get('domain', '')} {page_content}".strip(),
            keywords=phishing_keywords,
        )
        has_phishing_keywords = bool(keyword_matches["exact"] or keyword_matches["fuzzy"])
        detected_language = features.get("detectedLanguage", "en")
        attack_categories = {
            (doc.get("attackCategory") or "").lower()
            for doc in threat_intel_matches
            if doc.get("score", 0) >= thresholds.get("threatIntelMinScore", 0.85)
        }
        source_collections = {
            (doc.get("_sourceCollection") or "").lower()
            for doc in threat_intel_matches
        }

        phishing_like_categories = {
            "government_impersonation",
            "banking_scam",
            "credential_harvesting",
            "phishing",
            "qr_phishing",
            "upi_fraud",
            "shortener_abuse",
        }

        domain = (features.get("domain") or "").lower()
        is_shortener = domain in KNOWN_SHORTENERS
        is_upi = (features.get("rawUrl") or "").startswith("upi://")
        query_params = features.get("queryParams") or {}
        has_qr_hint = "qr" in (features.get("rawUrl") or "").lower() or any(
            any(str(v).lower().startswith("qr_") or str(v).lower() == "qr" for v in values)
            for values in query_params.values()
        )

        if attack_categories & phishing_like_categories:
            return "phishing"

        if "regional_threats" in source_collections and detected_language != "en":
            return "phishing"

        if is_shortener or is_upi or has_qr_hint:
            return "phishing"

        if has_phishing_keywords and features.get("brandImpersonation", {}).get("closest_brand"):
            return "phishing"

        return classification

    async def scan_url(self, url: str, page_content: str = "") -> dict:
        """Full URL scanning pipeline with waterfall enforcement.

        Tier 1 — L1 cache (< 1ms): Check in-memory LRU for recent result
        Tier 2 — L2 MongoDB (< 10ms): Exact URL lookup in urls collection
        Tier 3 — L3 full pipeline: Feature extraction → Embedding → Vector search
        """
        start = time.monotonic()
        logger.info("Scanning URL: %s", url)
        normalized_page_content = self._normalize_page_content(page_content)
        cache_key = self._build_cache_key(url, normalized_page_content)

        # Load admin-configurable rules (cached per request)
        rules = None
        if self._rules_repo:
            try:
                rules = await self._rules_repo.get_rules()
            except Exception as e:
                logger.warning("Failed to load scan rules, using defaults: %s", e)

        # ── L1: In-memory cache check ────────────────────────────────────
        cached = self._cache.get(cache_key)
        if cached:
            elapsed = (time.monotonic() - start) * 1000
            cached["waterfallTier"] = "L1_CACHE"
            cached["latencyMs"] = round(elapsed, 2)
            logger.info("L1 cache hit for %s (%.2fms)", url, elapsed)
            return cached

        scanned_domain = self._extract_domain(url)
        canonical_domain = self._canonical_domain(scanned_domain)

        # ── L2: MongoDB exact-URL lookup + canonical authority ───────────
        existing = await self._url_repo.find_by_url(url)
        canonical_authority = None
        if canonical_domain:
            try:
                canonical_authority = await self._url_repo.find_latest_by_canonical_domain(canonical_domain)
            except Exception as e:
                logger.warning("Canonical domain lookup failed for %s: %s", canonical_domain, e)

        if existing and existing.get("embedding") and not normalized_page_content:
            elapsed = (time.monotonic() - start) * 1000
            logger.info("L2 DB hit for %s (%.2fms)", url, elapsed)
            # Re-run vector search with stored embedding for fresh intel
            result = await self._run_full_analysis(
                url, existing_record=existing, existing_embedding=existing["embedding"],
                authoritative_record=canonical_authority,
                canonical_domain=canonical_domain,
                rules=rules,
                page_content=normalized_page_content,
            )
            result["waterfallTier"] = "L2_DATABASE"
            result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
            self._cache.put(cache_key, result)
            return result

        # ── L3: Full analysis pipeline ───────────────────────────────────
        result = await self._run_full_analysis(
            url,
            existing_record=existing,
            authoritative_record=canonical_authority,
            canonical_domain=canonical_domain,
            rules=rules,
            page_content=normalized_page_content,
        )
        result["waterfallTier"] = "L3_FULL_PIPELINE"
        result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
        self._cache.put(cache_key, result)
        logger.info("L3 full pipeline for %s (%.2fms)", url, result["latencyMs"])
        return result

    async def _run_full_analysis(
        self, url: str,
        existing_record: dict = None,
        existing_embedding: list = None,
        authoritative_record: dict = None,
        canonical_domain: str = "",
        rules: dict = None,
        page_content: str = "",
    ) -> dict:
        """Run the complete analysis pipeline."""

        modules = (rules or {}).get("detectionModules", {})
        thresholds = (rules or {}).get("thresholds", {})
        weights = (rules or {}).get("riskWeights", None)
        hard_floors = (rules or {}).get("hardFloors", {})
        phishing_kw = (rules or {}).get("phishingKeywords", None)
        vector_limit = thresholds.get("vectorSearchLimit", 5)
        intel_min_score = thresholds.get("threatIntelMinScore", 0.85)
        block_score = thresholds.get("blockScore", 75)
        review_score = thresholds.get("reviewScore", 50)

        # 1. Feature extraction + advanced enrichment
        features = extract_features(url)
        features["rawUrl"] = url
        features["canonicalDomain"] = canonical_domain or self._canonical_domain(features.get("domain", ""))
        features = enrich_features(url, features, modules=modules)
        features["payloadTypes"] = detect_payload_types(url)
        features["detectedLanguage"] = build_scan_signals(url, features, page_content=page_content)["detected_language"]

        # 2. Build initial summary text for embedding (pre-classification)
        summary_text = build_summary_text(url, features)
        summary_text = self._append_page_content(summary_text, page_content)

        # 3. Generate embedding (or reuse existing)
        embedding = existing_embedding
        if not embedding:
            try:
                embedding = await get_embedding(summary_text)
            except Exception as e:
                logger.warning("Embedding generation failed: %s — proceeding without", e)
                embedding = None

        # 4. Unified vector search (single query against urls collection)
        #    Results include both scan records and threat intel entries.
        similar_threats = []
        threat_intel_matches = []
        max_similarity = 0.0
        max_intel_similarity = 0.0
        atlas_signals = {
            "query": "",
            "matchCount": 0,
            "maxSearchScore": 0.0,
            "matchedAttackCategories": [],
            "matchedPayloadSignatures": [],
        }
        scanned_domain = features["domain"].lower()
        vs_enabled = modules.get("vectorSearch", True)
        ti_enabled = modules.get("threatIntel", True)
        atlas_enabled = modules.get("atlasSearch", True)
        combined_limit = vector_limit + (10 if ti_enabled else 0)

        vector_search_ms: float = 0.0
        if embedding and vs_enabled:
            try:
                _vs_start = time.monotonic()
                raw_results = await self._vector_search.search_similar(
                    query_vector=embedding, limit=combined_limit
                )
                vector_search_ms = round((time.monotonic() - _vs_start) * 1000, 2)
                # Split results: scan docs vs threat intel docs
                for m in raw_results:
                    doc_type = m.get("docType", "scan")
                    m_url = (m.get("url") or "").lower()

                    if doc_type == "threat_intel":
                        if not ti_enabled:
                            continue
                        # Filter: skip intel entries that target/abuse the scanned domain
                        m_desc = (m.get("description") or "").lower()
                        if scanned_domain in m_url:
                            parsed_scanned = url.lower().rstrip("/")
                            parsed_threat = m_url.rstrip("/")
                            if parsed_threat != parsed_scanned:
                                continue
                        if "legitimate domain" in m_desc and scanned_domain in m_desc:
                            continue
                        if len(threat_intel_matches) < 5:
                            threat_intel_matches.append(m)
                            if not max_intel_similarity:
                                max_intel_similarity = m.get("score", 0.0)
                    else:
                        if len(similar_threats) < vector_limit:
                            similar_threats.append(m)
                            if not max_similarity:
                                max_similarity = m.get("score", 0.0)

            except Exception as e:
                logger.warning("Vector search failed: %s", e)

        # 4b. Multi-collection search (threat_signals, infra, regional, visual, behavior)
        multi_results = {}
        multi_search_ms: float = 0.0
        if self._multi and embedding:
            try:
                _mc_start = time.monotonic()
                # Determine scan signals for smart routing
                scan_signals = build_scan_signals(url, features, page_content=page_content)

                # Build embeddings for conditional collections (parallel)
                regional_embedding = None
                visual_embedding = None

                embedding_tasks = []
                embedding_keys = []

                if scan_signals["detected_language"] != "en":
                    regional_text = build_regional_text(url, page_content, features)
                    embedding_tasks.append(get_multilingual_embedding(regional_text))
                    embedding_keys.append("regional")

                if scan_signals["has_screenshot"]:
                    visual_desc = build_visual_description(url, features)
                    embedding_tasks.append(get_visual_embedding(visual_desc))
                    embedding_keys.append("visual")

                if embedding_tasks:
                    emb_results = await asyncio.gather(*embedding_tasks, return_exceptions=True)
                    for key, result in zip(embedding_keys, emb_results):
                        if isinstance(result, Exception):
                            logger.warning("Embedding for %s failed: %s", key, result)
                        elif key == "regional":
                            regional_embedding = result
                        elif key == "visual":
                            visual_embedding = result

                # Fan-out search across all relevant collections
                multi_results = await self._multi.search_all_collections(
                    domain=features["domain"],
                    threat_embedding=embedding,
                    regional_embedding=regional_embedding,
                    visual_embedding=visual_embedding,
                    has_infra_data=scan_signals["has_infra_data"],
                    has_traffic_anomaly=scan_signals["has_traffic_anomaly"],
                    check_fast_flux=features.get("dnsStatus") == "active" and features["hostingFlags"]["domainAgeDays"] < 30,
                    check_tls_anomaly=not features["hostingFlags"]["sslValid"],
                )
                multi_search_ms = round((time.monotonic() - _mc_start) * 1000, 2)

                # Merge threat_signals results into similar_threats
                for doc in multi_results.get("threat_signals", []):
                    if len(similar_threats) < combined_limit:
                        doc["score"] = doc.get("vectorScore", 0.0)
                        similar_threats.append(doc)
                        if doc["score"] > max_similarity:
                            max_similarity = doc["score"]

                # Merge infra/behavior/regional/visual into threat_intel_matches for risk scoring
                for coll_name in ("infrastructure_intel", "behavior_metrics", "regional_threats", "visual_intelligence"):
                    for doc in multi_results.get(coll_name, []):
                        score = doc.get("vectorScore") or doc.get("searchScore", 0.0)
                        doc["score"] = score
                        doc["_sourceCollection"] = coll_name
                        if len(threat_intel_matches) < 10:
                            threat_intel_matches.append(doc)
                            if score > max_intel_similarity:
                                max_intel_similarity = score

            except Exception as e:
                logger.warning("Multi-collection search failed: %s", e)

        # 4c. Atlas lexical enrichment (threat-intel focused)
        if self._atlas_search and atlas_enabled and ti_enabled:
            try:
                atlas_query = " ".join(filter(None, [
                    features.get("domain", ""),
                    *features.get("payloadTypes", [])[:2],
                ])).strip()
                atlas_signals["query"] = atlas_query
                if atlas_query:
                    atlas_res = await self._atlas_search.search(
                        query=atlas_query,
                        fuzzy_max_edits=1,
                        limit=8,
                    )
                    atlas_results = [
                        r for r in atlas_res.get("results", [])
                        if r.get("docType") == "threat_intel"
                    ]
                    atlas_signals["matchCount"] = len(atlas_results)
                    atlas_signals["maxSearchScore"] = max((r.get("score", 0.0) for r in atlas_results), default=0.0)
                    atlas_signals["matchedAttackCategories"] = list({
                        r.get("attackCategory") for r in atlas_results if r.get("attackCategory")
                    })[:6]
                    atlas_signals["matchedPayloadSignatures"] = list({
                        r.get("payloadSignature") for r in atlas_results if r.get("payloadSignature")
                    })[:6]
            except Exception as e:
                logger.warning("Atlas lexical enrichment failed: %s", e)

        # 5. Risk scoring (use best similarity from either source)
        best_similarity = max(max_similarity, max_intel_similarity)
        risk, risk_breakdown = calculate_risk_score(
            features, best_similarity, weights=weights,
            url=url, hard_floors=hard_floors, phishing_keywords=phishing_kw,
            intel_match_count=len(threat_intel_matches),
            max_intel_similarity=max_intel_similarity,
            atlas_match_count=atlas_signals["matchCount"],
            max_atlas_score=atlas_signals["maxSearchScore"],
        )
        classification = classify_threat(risk, thresholds=thresholds)
        classification = self._refine_classification(
            classification=classification,
            risk=risk,
            thresholds=thresholds,
            features=features,
            threat_intel_matches=threat_intel_matches,
            page_content=page_content,
        )

        authority = authoritative_record
        risk_alignment_note = None
        if authority and authority.get("url") and authority.get("url") != url:
            authority_risk = authority.get("riskScore")
            if authority_risk is not None:
                try:
                    aligned_risk = round(float(authority_risk), 1)
                    if aligned_risk != risk:
                        prior_risk = risk
                        risk = aligned_risk
                        classification = classify_threat(risk, thresholds=thresholds)
                        risk_breakdown.append({
                            "factor": "Canonical Domain Alignment",
                            "key": "canonicalAlignment",
                            "raw": aligned_risk,
                            "weight": 1.0,
                            "contribution": round(aligned_risk - prior_risk, 2),
                            "sourceUrl": authority.get("url"),
                        })
                        risk_alignment_note = (
                            f"Risk score aligned to canonical peer URL '{authority.get('url')}' "
                            f"for domain family '{features['canonicalDomain']}'."
                        )
                except (TypeError, ValueError):
                    pass

        # 6. Rebuild summary text with ALL fields (classification, risk, status, scanCount)
        now = datetime.utcnow()
        payload_types = features.get("payloadTypes", [])
        scan_count = (existing_record.get("scanCount", 0) + 1) if existing_record else 1
        computed_status = "blocked" if risk >= block_score else ("under_review" if risk >= review_score else "allowed")

        # ── Status lock: preserve canonical-domain authoritative status ──
        status_override_note = None
        if authority and authority.get("status"):
            prev_status = authority["status"]
            status_val = prev_status  # keep the authoritative status
            if prev_status != computed_status:
                _status_labels = {
                    "blocked": "blocked by authorities",
                    "under_review": "under review by authorities",
                    "allowed": "allowed by authorities",
                }
                status_override_note = (
                    f"This URL was previously {_status_labels.get(prev_status, prev_status)}. "
                    f"The current scan produced a score of {risk}/100 "
                    f"(which would normally be '{computed_status}'), but the authoritative "
                    f"status of '{prev_status}' has been preserved."
                )
        else:
            status_val = computed_status

        if risk_alignment_note:
            status_override_note = f"{status_override_note} {risk_alignment_note}" if status_override_note else risk_alignment_note

        summary_text = build_summary_text(
            url, features,
            classification=classification,
            risk_score=risk,
            status=status_val,
            scan_count=scan_count,
        )
        summary_text = self._append_page_content(summary_text, page_content)

        # 7. Build record
        record = {
            "url": url,
            "domain": features["domain"],
            "canonicalDomain": features["canonicalDomain"],
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
            "status": status_val,
            "reviewedBy": "system_ai",
            "summaryText": summary_text,
            "embedding": embedding,
            "atlasSignals": atlas_signals,
            # ── New metadata ──────────────────────────────────────────
            "queryParams": features.get("queryParams", {}),
            "payloadTypes": payload_types,
            "redirectChain": None,   # populated by enricher when available
            "tlsCertificate": None,  # populated by enricher when available
            "whoisData": None,       # populated by enricher when available
            "scanCount": scan_count,
            "firstSeenAt": existing_record.get("firstSeenAt", now) if existing_record else now,
            "lastSeenAt": now,
            "relatedDomains": [],    # populated by graph service
            "campaignId": existing_record.get("campaignId") if existing_record else None,
            "campaignName": existing_record.get("campaignName") if existing_record else None,
            "statusNote": status_override_note,
            "canonicalAuthorityUrl": authority.get("url") if authority else None,
            "createdAt": existing_record.get("createdAt", now) if existing_record else now,
            "updatedAt": now,
        }

        # 8. Persist (upsert — update if URL already exists)
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

        # 9. Build relationship graph edges (fire-and-forget)
        if self._graph_service and (similar_threats or threat_intel_matches):
            try:
                await self._graph_service.build_edges_from_scan(
                    scanned_url=url,
                    scanned_record=record,
                    similar_threats=similar_threats,
                    threat_intel_matches=[],  # intel matches are feeds, not URLs
                )
            except Exception as e:
                logger.warning("Graph edge creation failed: %s", e)

        # 10. Campaign detection — cluster vector neighbours into campaigns
        campaign = None
        if self._campaign_service and (similar_threats or threat_intel_matches):
            try:
                campaign = await self._campaign_service.detect_and_tag(
                    scanned_url=url,
                    scanned_domain=features["domain"],
                    scanned_risk=risk,
                    scanned_classification=classification,
                    similar_threats=similar_threats,
                    threat_intel_matches=threat_intel_matches,
                    atlas_signals=atlas_signals,
                    url_record=record,
                )
                if campaign:
                    record["campaignId"] = campaign["_id"]
                    record["campaignName"] = campaign.get("name")
                    # Re-embed synchronously with campaign context baked in.
                    # The stored embedding now carries both URL threat signals and
                    # campaign semantics — a single vector query is sufficient for
                    # all future lookups (no second query or background task needed).
                    try:
                        enriched_summary = build_campaign_enriched_summary(
                            url=url,
                            features=features,
                            campaign=campaign,
                            classification=classification,
                            risk_score=risk,
                            status=status_val,
                            scan_count=scan_count,
                        )
                        enriched_embedding = await get_embedding(enriched_summary)
                        record["summaryText"] = enriched_summary
                        record["embedding"] = enriched_embedding
                    except Exception as emb_err:
                        logger.warning("Campaign re-embed failed: %s — keeping base embedding", emb_err)
                    await self._url_repo.update_one(
                        record["_id"],
                        {
                            "campaignId": record["campaignId"],
                            "campaignName": record["campaignName"],
                            "summaryText": record["summaryText"],
                            "embedding": record["embedding"],
                        },
                    )
            except Exception as e:
                logger.warning("Campaign detection failed: %s", e)

        # If no fresh campaign was detected, hydrate from existing linkage.
        if not campaign and self._campaign_service:
            campaign_ref = record.get("campaignId")
            if campaign_ref:
                try:
                    campaign = await self._campaign_service.get_campaign(campaign_ref)
                    if campaign:
                        record["campaignName"] = campaign.get("name")
                except Exception as e:
                    logger.warning("Campaign hydration failed for %s: %s", campaign_ref, e)

        result = {
            "urlRecord": record,
            "similarThreats": similar_threats,
            "threatIntelMatches": threat_intel_matches,
            "atlasSearchSignals": atlas_signals,
            "multiCollectionResults": {
                k: len(v) for k, v in multi_results.items()
            } if multi_results else {},
            "campaign": campaign,
            "recommendedAction": recommended_action(risk, thresholds=thresholds),
            "riskLevel": risk_level(risk, thresholds=thresholds),
            "riskBreakdown": risk_breakdown,
            "vectorSearchMs": vector_search_ms,
            "multiCollectionSearchMs": multi_search_ms,
            "analysisSummary": self._build_analysis_summary(
                url, features, classification, risk, record["status"],
                similar_threats, threat_intel_matches,
                max_similarity, max_intel_similarity,
                rules=rules,
            ),
        }
        if status_override_note:
            result["statusOverrideNote"] = status_override_note
            result["analysisSummary"]["statusOverrideNote"] = status_override_note
        return result

    @staticmethod
    def _slim_doc(doc, extra_fields=None):
        """Minimal representation of a matched document for the summary."""
        slim = {
            "_id": str(doc.get("_id", "")),
            "url": doc.get("url"),
            "domain": doc.get("domain"),
            "riskScore": doc.get("riskScore"),
            "status": doc.get("status"),
            "score": doc.get("score"),
            "threatClassification": doc.get("threatClassification"),
        }
        for f in (extra_fields or []):
            if f in doc:
                slim[f] = doc[f]
        return slim

    @staticmethod
    def _slim_intel(doc):
        """Minimal representation of a threat-intel match."""
        feed_metadata = doc.get("feedMetadata", {})
        feed_name = URLAnalysisService._intel_feed_name(doc)
        
        # Use summaryText as fallback for description (threat_signals use summaryText)
        description = doc.get("description") or doc.get("summaryText", "")
        
        # Clamp score to [0, 1] range to prevent >100% display
        score = doc.get("score", 0)
        score = min(1.0, max(0, score))
        
        return {
            "_id": str(doc.get("_id", "")),
            "url": doc.get("url"),
            "feedName": feed_name,
            "threatType": URLAnalysisService._intel_pattern_type(doc),
            "description": description,
            "score": score,
            "reportedDate": str(doc.get("submissionDate") or doc.get("reportedDate", "")),
            "attackCategory": doc.get("attackCategory", ""),
            "targetDomain": doc.get("targetDomain", ""),
            "severity": feed_metadata.get("severity") or doc.get("severity", ""),
            "confidence": feed_metadata.get("confidence") or doc.get("confidence"),
        }

    def _build_analysis_summary(
        self, url, features, classification, risk, status,
        similar_threats, threat_intel_matches,
        max_similarity, max_intel_similarity,
        rules=None,
    ) -> dict:
        """Build a human-readable analysis summary with full explainability.

        Each reason is now a structured dict:
          { "text": str, "tag": str|None, "matchedDocs": list[dict] }
        When the Vector DB blocks a URL because it is 'mathematically close'
        to a threat, we translate that into concrete, human-readable reasons
        and attach the actual MongoDB documents that contributed to the flag.
        """
        reasons = []
        domain = features["domain"]
        hf = features["hostingFlags"]
        us = features["urlStructure"]
        modules = (rules or {}).get("detectionModules", {})
        r_thresholds = (rules or {}).get("thresholds", {})
        r_kw_list = (rules or {}).get("phishingKeywords", None)

        def _reason(text, tag=None, matched_docs=None):
            return {"text": text, "tag": tag, "matchedDocs": matched_docs or []}

        # ── DGA detection reasons ────────────────────────────────────────
        dga = features.get("dgaAnalysis")
        if dga and dga.get("isDGA"):
            dga_docs = [
                self._slim_doc(t, extra_fields=["dgaAnalysis"])
                for t in similar_threats
                if (t.get("dgaAnalysis") or {}).get("isDGA")
            ]
            reasons.append(_reason(
                f"⚙️ DGA DETECTED (score: {dga['dgaScore']:.0%}) — This domain appears to be "
                "algorithmically generated (similar to Suppobox/Mirai patterns). "
                "DGA domains are created by malware to evade static blacklists.",
                tag="dga", matched_docs=dga_docs,
            ))
            for sig in dga.get("dgaSignals", [])[:2]:
                reasons.append(_reason(f"  ↳ {sig}"))

        # ── Homoglyph / typosquat reasons ────────────────────────────────
        homoglyph = features.get("homoglyphAnalysis")
        if homoglyph and homoglyph.get("hasHomoglyphs"):
            target = homoglyph.get("targetDomain", "a government portal")
            hg_docs = [
                self._slim_doc(t, extra_fields=["homoglyphAnalysis"])
                for t in similar_threats
                if (t.get("homoglyphAnalysis") or {}).get("hasHomoglyphs")
            ]
            reasons.append(_reason(
                f"👁️ VISUAL IMPERSONATION — This domain uses characters that "
                f"visually mimic '{target}'. Attackers use look-alike characters "
                "(Cyrillic, digit/letter swaps) to trick users.",
                tag="homoglyph", matched_docs=hg_docs,
            ))
            for sig in homoglyph.get("homoglyphSignals", [])[:2]:
                reasons.append(_reason(f"  ↳ {sig}"))

        # ── Brand impersonation / typosquatting reasons ────────────────
        brand = features.get("brandImpersonation")
        if brand and not brand.get("is_exact_match") and 0 < brand.get("edit_distance", 999) <= 3:
            bi_docs = [
                self._slim_doc(t, extra_fields=["brandImpersonation"])
                for t in similar_threats
                if (t.get("brandImpersonation") or {}).get("closest_brand")
                and not (t.get("brandImpersonation") or {}).get("is_exact_match")
                and 0 < (t.get("brandImpersonation") or {}).get("edit_distance", 999) <= 3
            ]
            reasons.append(_reason(
                f"🏛️ BRAND IMPERSONATION — Domain is {brand['edit_distance']} character(s) away from "
                f"known government domain '{brand['known_domain']}' ({brand['closest_brand']}). "
                "Typosquatting domains mimic trusted sites to steal credentials.",
                tag="brand_impersonation", matched_docs=bi_docs,
            ))

        # ── Phishing keyword reasons ─────────────────────────────────────
        _PHISHING_KW = set(r_kw_list) if r_kw_list else {
            "login", "signin", "verify", "secure", "account", "update",
            "confirm", "banking", "password", "credential", "auth",
            "portal", "validate", "suspend", "unlock", "otp", "kyc",
        }
        kw_matches = find_phishing_keyword_matches(
            text=f"{domain.lower()} {url.lower()}",
            keywords=_PHISHING_KW,
            max_edit_distance=2,
            long_keyword_edit_distance=3,
        )
        kw_found = kw_matches["allKeywords"]
        if kw_found:
            kw_docs = [
                self._slim_doc(t)
                for t in similar_threats
                if t.get("status") == "blocked"
                and any(kw in (t.get("url") or "").lower() for kw in kw_found)
            ]
            fuzzy_hits = kw_matches["fuzzy"]
            fuzzy_note = ""
            if fuzzy_hits:
                top_fuzzy = ", ".join(
                    f"{m['token']}~{m['keyword']} (d={m['distance']})"
                    for m in fuzzy_hits[:3]
                )
                fuzzy_note = (
                    f" Typo-tolerant matches detected: {top_fuzzy}."
                )
            reasons.append(_reason(
                f"🎣 PHISHING KEYWORDS — URL contains {len(kw_found)} social engineering "
                f"keyword(s): {', '.join(kw_found)}. These terms are used to create urgency "
                f"and trick users into submitting credentials.{fuzzy_note}",
                tag="phishing_keywords", matched_docs=kw_docs,
            ))

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
            bp_docs = [
                self._slim_doc(t, extra_fields=["structuralAnalysis"])
                for t in similar_threats
                if (t.get("structuralAnalysis") or {}).get("bypassTechniques")
            ]
            reasons.append(_reason(
                f"🛡️ BYPASS TECHNIQUES ({len(techniques)}) — "
                f"Detected: {', '.join(names)}. These techniques would "
                "evade standard regex/rule-based filters.",
                tag="bypass", matched_docs=bp_docs,
            ))
            for sig in structural.get("structuralSignals", [])[:3]:
                reasons.append(_reason(f"  ↳ {sig}"))

        # ── Domain-level risks ───────────────────────────────────────────
        if hf["domainAgeDays"] < 30:
            reasons.append(_reason(f"Domain is only {hf['domainAgeDays']} days old — newly registered domains are commonly used in attacks"))
        elif hf["domainAgeDays"] < 180:
            reasons.append(_reason(f"Domain is {hf['domainAgeDays']} days old — relatively new domain"))

        if not hf["sslValid"]:
            reasons.append(_reason("No valid SSL certificate — legitimate government sites always use HTTPS with valid certificates"))

        tld_risk = features.get("tldRisk")
        if tld_risk and tld_risk.get("tldRisk") == "high":
            reasons.append(_reason(f"Uses high-risk TLD (.{domain.split('.')[-1]}) — {tld_risk.get('tldNote', 'frequently abused')}"))
        elif us.get("hasSuspiciousTld"):
            reasons.append(_reason(f"Uses suspicious TLD (.{domain.split('.')[-1]}) — commonly associated with malicious domains"))

        if us.get("hasIpAddress"):
            reasons.append(_reason("Domain contains an IP address instead of a hostname — typical of phishing/C2 infrastructure"))

        if us.get("entropyScore", 0) > 4.5:
            reasons.append(_reason(f"High URL entropy ({us['entropyScore']:.2f}) — randomized characters suggest auto-generated malicious URL"))

        if us.get("containsEncodedChars"):
            reasons.append(_reason("Contains encoded characters — may be attempting to obfuscate malicious payload"))

        if features["dnsStatus"] in ("suspended", "parked"):
            reasons.append(_reason(f"DNS status is '{features['dnsStatus']}' — domain is not actively serving legitimate content"))

        if hf.get("isSharedHosting"):
            reasons.append(_reason("Hosted on shared infrastructure — common for low-cost malicious hosting"))

        # ── Vector search explainability ─────────────────────────────────
        blocked_similar = [t for t in similar_threats if t.get("status") == "blocked"]
        malicious_similar = [t for t in similar_threats if t.get("threatClassification") in ("phishing", "malware", "c2")]
        if blocked_similar:
            vec_docs = [self._slim_doc(t) for t in blocked_similar]
            reasons.append(_reason(
                f"🔗 VECTOR MATCH — Matches {len(blocked_similar)} previously blocked URL(s) "
                f"with up to {max_similarity * 100:.0f}% cosine similarity in the embedding space. "
                "This means the URL's structural DNA closely resembles known threats.",
                tag="vector_match", matched_docs=vec_docs,
            ))
        elif malicious_similar:
            vec_docs = [self._slim_doc(t) for t in malicious_similar]
            reasons.append(_reason(
                f"🔗 SEMANTIC PROXIMITY — Semantically similar to {len(malicious_similar)} known threat(s) "
                f"({max_similarity * 100:.0f}% similarity). The URL's features cluster near known malicious URLs "
                "in vector space even though it may not appear on any blacklist.",
                tag="semantic_proximity", matched_docs=vec_docs,
            ))

        # ── Threat intel explainability ──────────────────────────────────
        # Only surface threat intel matches at configured min score to avoid
        # false-positive noise from generic domain-family matches.
        _intel_min = r_thresholds.get("threatIntelMinScore", 0.85)
        high_conf_intel = [t for t in threat_intel_matches if t.get("score", 0) >= _intel_min]
        if high_conf_intel:
            feeds = list(set(self._intel_feed_name(t) for t in high_conf_intel[:3]))
            types = list(set(self._intel_pattern_type(t) for t in high_conf_intel))
            top_score = min(1.0, high_conf_intel[0].get("score", 0))  # Clamp to [0,1] range
            intel_docs = [self._slim_intel(t) for t in high_conf_intel]
            reasons.append(_reason(
                f"📡 THREAT INTEL — Similar to {len(high_conf_intel)} "
                f"{'/'.join(types)} pattern(s) reported by {', '.join(feeds)} "
                f"at up to {top_score * 100:.0f}% vector similarity.",
                tag="threat_intel", matched_docs=intel_docs,
            ))

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
        classification: Optional[str] = None, domain: Optional[str] = None,
    ) -> dict:
        filter_doc: dict = {}
        if status:
            filter_doc["status"] = status
        if classification:
            filter_doc["threatClassification"] = classification
        if domain:
            # Match either the baseDomain (canonical anchor) or the exact domain
            filter_doc["$or"] = [
                {"baseDomain": domain},
                {"domain": domain},
            ]
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
            self._cache.invalidate_url(url_doc.get("url", ""))
        _status_labels = {
            "blocked": "Blocked by authorities",
            "under_review": "Flagged for review by authorities",
            "allowed": "Approved by authorities",
        }
        status_note = _status_labels.get(status, f"Status set to {status}")
        return await self._url_repo.update_one(
            url_id, {
                "status": status,
                "statusNote": status_note,
                "updatedAt": datetime.utcnow(),
            }
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
