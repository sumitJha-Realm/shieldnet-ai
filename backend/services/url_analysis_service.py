"""URL analysis service — core scanning logic."""

import logging
import time
from datetime import datetime
from typing import Optional

from repositories.impl.url_repository import URLRepository
from repositories.impl.scan_rules_repository import ScanRulesRepository
from services.embedding_service import get_embedding
from services.search.vector_search_service import VectorSearchService
from services.waterfall_cache import WaterfallCache
from services.url_graph_service import URLGraphService
from utils.url_feature_extractor import (
    extract_features,
    enrich_features,
    build_summary_text,
    calculate_risk_score,
    classify_threat,
    risk_level,
    recommended_action,
    detect_payload_types,
    classify_payload_severity,
    derive_payload_signature,
)

logger = logging.getLogger(__name__)


class URLAnalysisService:
    def __init__(
        self,
        url_repo: URLRepository,
        vector_search_service: "VectorSearchService",
        cache: Optional["WaterfallCache"] = None,
        rules_repo: Optional["ScanRulesRepository"] = None,
        graph_service: Optional["URLGraphService"] = None,
    ):
        self._url_repo = url_repo
        self._vector_search = vector_search_service
        self._cache = cache or WaterfallCache()
        self._rules_repo = rules_repo
        self._graph_service = graph_service

    async def scan_url(self, url: str) -> dict:
        """Full URL scanning pipeline with waterfall enforcement.

        Tier 1 — L1 cache (< 1ms): Check in-memory LRU for recent result
        Tier 2 — L2 MongoDB (< 10ms): Exact URL lookup in urls collection
        Tier 3 — L3 full pipeline: Feature extraction → Embedding → Vector search
        """
        start = time.monotonic()
        logger.info("Scanning URL: %s", url)

        # Load admin-configurable rules (cached per request)
        rules = None
        if self._rules_repo:
            try:
                rules = await self._rules_repo.get_rules()
            except Exception as e:
                logger.warning("Failed to load scan rules, using defaults: %s", e)

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
                rules=rules,
            )
            result["waterfallTier"] = "L2_DATABASE"
            result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
            self._cache.put(url, result)
            return result

        # ── L3: Full analysis pipeline ───────────────────────────────────
        result = await self._run_full_analysis(url, rules=rules)
        result["waterfallTier"] = "L3_FULL_PIPELINE"
        result["latencyMs"] = round((time.monotonic() - start) * 1000, 2)
        self._cache.put(url, result)
        logger.info("L3 full pipeline for %s (%.2fms)", url, result["latencyMs"])
        return result

    async def _run_full_analysis(
        self, url: str,
        existing_record: dict = None,
        existing_embedding: list = None,
        rules: dict = None,
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
        features = enrich_features(url, features, modules=modules)
        features["payloadTypes"] = detect_payload_types(url)

        # 2. Build initial summary text for embedding (pre-classification)
        summary_text = build_summary_text(url, features)

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
        scanned_domain = features["domain"].lower()
        vs_enabled = modules.get("vectorSearch", True)
        ti_enabled = modules.get("threatIntel", True)
        combined_limit = vector_limit + (10 if ti_enabled else 0)

        if embedding and vs_enabled:
            try:
                raw_results = await self._vector_search.search_similar(
                    query_vector=embedding, limit=combined_limit
                )
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

        # 5. Risk scoring (use best similarity from either source)
        best_similarity = max(max_similarity, max_intel_similarity)
        risk, risk_breakdown = calculate_risk_score(
            features, best_similarity, weights=weights,
            url=url, hard_floors=hard_floors, phishing_keywords=phishing_kw,
            intel_match_count=len(threat_intel_matches),
            max_intel_similarity=max_intel_similarity,
        )
        classification = classify_threat(risk, thresholds=thresholds)

        # 6. Rebuild summary text with ALL fields (classification, risk, status, scanCount)
        now = datetime.utcnow()
        payload_types = features.get("payloadTypes", [])
        scan_count = (existing_record.get("scanCount", 0) + 1) if existing_record else 1
        computed_status = "blocked" if risk >= block_score else ("under_review" if risk >= review_score else "allowed")

        # ── Status lock: on exact URL re-scan, preserve the previous status ──
        status_override_note = None
        if existing_record and existing_record.get("status"):
            prev_status = existing_record["status"]
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
        summary_text = build_summary_text(
            url, features,
            classification=classification,
            risk_score=risk,
            status=status_val,
            scan_count=scan_count,
        )

        # 7. Build record
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
            "status": status_val,
            "reviewedBy": "system_ai",
            "summaryText": summary_text,
            "embedding": embedding,
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
            "statusNote": status_override_note,
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

        result = {
            "urlRecord": record,
            "similarThreats": similar_threats,
            "threatIntelMatches": threat_intel_matches,
            "recommendedAction": recommended_action(risk, thresholds=thresholds),
            "riskLevel": risk_level(risk, thresholds=thresholds),
            "riskBreakdown": risk_breakdown,
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
        return {
            "_id": str(doc.get("_id", "")),
            "url": doc.get("url"),
            "feedName": doc.get("feedName") or doc.get("source", ""),
            "threatType": doc.get("threatClassification") or doc.get("threatType"),
            "description": doc.get("description"),
            "score": doc.get("score"),
            "reportedDate": str(doc.get("submissionDate") or doc.get("reportedDate", "")),
            "attackCategory": doc.get("attackCategory", ""),
            "targetDomain": doc.get("targetDomain", ""),
            "severity": doc.get("severity", ""),
            "confidence": doc.get("confidence"),
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
        url_lower = url.lower()
        kw_found = [kw for kw in _PHISHING_KW if kw in url_lower]
        if kw_found:
            kw_docs = [
                self._slim_doc(t)
                for t in similar_threats
                if t.get("status") == "blocked"
                and any(kw in (t.get("url") or "").lower() for kw in kw_found)
            ]
            reasons.append(_reason(
                f"🎣 PHISHING KEYWORDS — URL contains {len(kw_found)} social engineering "
                f"keyword(s): {', '.join(kw_found)}. These terms are used to create urgency "
                "and trick users into submitting credentials.",
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
            feeds = list(set(t.get("feedName", "Unknown") for t in high_conf_intel[:3]))
            types = list(set(t.get("threatType", "unknown") for t in high_conf_intel))
            top_score = high_conf_intel[0].get("score", 0)
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
