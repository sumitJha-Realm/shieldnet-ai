"""Scan rules model — all configurable parameters for the scanning pipeline."""

from __future__ import annotations

# Default rules shipped with the system.  Stored in MongoDB collection
# "scan_rules" as a single document (singleton pattern).

DEFAULT_SCAN_RULES: dict = {
    "_id": "active_rules",

    # ── Detection module toggles ────────────────────────────────────
    "detectionModules": {
        "dgaDetection": True,
        "homoglyphDetection": True,
        "brandImpersonation": True,
        "phishingKeywords": True,
        "structuralBypass": True,
        "vectorSearch": True,
        "threatIntel": True,
    },

    # ── Risk scoring weights (must sum to ~1.0) ─────────────────────
    "riskWeights": {
        "domainAge": 0.10,
        "ssl": 0.03,
        "entropy": 0.05,
        "dns": 0.05,
        "hosting": 0.03,
        "vectorSimilarity": 0.15,
        "dgaScore": 0.08,
        "structuralScore": 0.10,
        "homoglyphScore": 0.08,
        "brandImpersonation": 0.15,
        "payloadRisk": 0.18,
    },

    # ── Thresholds ──────────────────────────────────────────────────
    "thresholds": {
        "blockScore": 75,
        "reviewScore": 50,
        "classifyPhishing": 80,
        "classifyMalware": 60,
        "classifySuspicious": 40,
        "threatIntelMinScore": 0.85,
        "vectorSearchLimit": 5,
    },

    # ── Hard floors (minimum score overrides) ───────────────────────
    "hardFloors": {
        "homoglyphVisualSimilarity": 75,
        "brandDist1": 78,
        "brandDist1WithKeywords": 85,
        "brandDist2": 60,
        "brandDist2WithKeywords": 72,
        "brandDist3WithKeywords": 55,
        "youngDomain7d": 65,
        "youngDomain30d": 55,
    },

    # ── Phishing keywords ───────────────────────────────────────────
    "phishingKeywords": [
        "login", "signin", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "credential", "auth",
        "portal", "validate", "suspend", "unlock", "otp", "kyc",
    ],

    # ── Suspicious TLDs ─────────────────────────────────────────────
    "suspiciousTlds": [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
        ".club", ".work", ".icu", ".cam", ".monster", ".rest", ".fit",
    ],
}
