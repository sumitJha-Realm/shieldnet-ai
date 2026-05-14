"""Models for multi-collection threat detection (25 UC coverage)."""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class SignalType(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    C2 = "c2"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BRAND_IMPERSONATION = "brand_impersonation"
    DARK_WEB_INTEL = "dark_web_intel"
    THREAT_INTEL = "threat_intel"
    QR_PHISHING = "qr_phishing"
    UPI_FRAUD = "upi_fraud"
    SUPPLY_CHAIN = "supply_chain"
    CAMPAIGN = "campaign"


class InfraStatus(str, Enum):
    ACTIVE = "active"
    FAST_FLUX = "fast-flux"
    DNS_TUNNELING = "dns-tunneling"
    RECENTLY_REACTIVATED = "recently-reactivated"
    BULLETPROOF = "bulletproof"
    INACTIVE = "inactive"


# ─── threat_signals collection (vector search with voyage-3-large) ───────


class ThreatSignalDoc(BaseModel):
    """Document in threat_signals collection. Covers UC 3,4,7,8,11,12,13,14,19,22,23."""
    id: Optional[str] = Field(None, alias="_id")
    url: str
    domain: str
    docType: str = "threat_signal"
    attackCategory: str = ""
    threatClassification: str = ""
    summaryText: str = ""
    embedding: Optional[list[float]] = None  # 1024-dim voyage-3-large
    source: str = "scanner"
    riskScore: float = 0.0
    relatedDomains: list[str] = Field(default_factory=list)
    indicators: dict = Field(default_factory=dict)
    feedMetadata: Optional[dict] = None
    qrMetadata: Optional[dict] = None
    campaignId: Optional[str] = None
    discoveredAt: datetime = Field(default_factory=datetime.utcnow)
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ─── infrastructure_intel collection (Atlas Search only, NO vector) ──────


class InfrastructureIntelDoc(BaseModel):
    """Document in infrastructure_intel collection. Covers UC 2,5,16,17,22.
    Uses Atlas Search (compound/range) only — no embedding needed."""
    id: Optional[str] = Field(None, alias="_id")
    domain: str
    ip: Optional[str] = None
    asn: str = ""
    asnName: str = ""
    hostingProvider: str = ""
    status: InfraStatus = InfraStatus.ACTIVE
    # DNS fields
    ipRotationCount24h: int = 0
    ttlSeconds: int = 3600
    nsServers: list[str] = Field(default_factory=list)
    mxRecords: list[str] = Field(default_factory=list)
    resolvedIps: list[str] = Field(default_factory=list)
    # TLS fields
    tlsIssuer: str = ""
    tlsValidDays: int = 0
    tlsSanMismatch: bool = False
    tlsSelfSigned: bool = False
    # Redirect chain
    redirectChainLength: int = 0
    redirectDomains: list[str] = Field(default_factory=list)
    # Supply chain
    cdnProvider: Optional[str] = None
    servesScripts: bool = False
    # Geo
    geoCountry: str = ""
    # Metadata
    firstSeenAt: datetime = Field(default_factory=datetime.utcnow)
    lastSeenAt: datetime = Field(default_factory=datetime.utcnow)
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ─── regional_threats collection (vector search with voyage-multilingual-2)


class RegionalThreatDoc(BaseModel):
    """Document in regional_threats collection. Covers UC 18, 24."""
    id: Optional[str] = Field(None, alias="_id")
    url: str
    domain: str
    language: str = "hi"  # ISO 639-1
    originalText: str = ""
    translatedText: str = ""
    summaryText: str = ""
    embedding: Optional[list[float]] = None  # 1024-dim voyage-multilingual-2
    attackCategory: str = ""
    targetBrand: str = ""
    region: str = ""
    riskScore: float = 0.0
    source: str = "regional_monitor"
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ─── visual_intelligence collection (vector search with voyage-multimodal-3)


class VisualIntelligenceDoc(BaseModel):
    """Document in visual_intelligence collection. Covers UC 10, 11, 21."""
    id: Optional[str] = Field(None, alias="_id")
    url: str
    domain: str
    type: str = "baseline"  # baseline | phishing_capture | watering_hole_diff
    brandName: str = ""
    screenshotHash: str = ""
    description: str = ""
    embedding: Optional[list[float]] = None  # 1024-dim voyage-multimodal-3
    similarityToBaseline: Optional[float] = None
    capturedAt: datetime = Field(default_factory=datetime.utcnow)
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ─── behavior_metrics collection (Atlas Search only, NO vector) ──────────


class BehaviorMetricsDoc(BaseModel):
    """Document in behavior_metrics collection. Covers UC 9, 20, 25.
    Uses Atlas Search (range queries) only — no embedding needed."""
    id: Optional[str] = Field(None, alias="_id")
    domain: str
    url: Optional[str] = None
    # Traffic metrics
    requestsPerMinute: float = 0.0
    uniqueIps: int = 0
    avgResponseTimeMs: float = 0.0
    errorRate4xx: float = 0.0
    errorRate5xx: float = 0.0
    # Bot indicators
    headerEntropy: float = 0.5
    avgTimeBetweenRequests: float = 1000.0
    userAgentVariety: int = 1
    hasCaptchaBypass: bool = False
    # Anomaly flags
    isAnomaly: bool = False
    anomalyType: str = ""  # traffic_spike, bot_swarm, credential_stuffing
    zScoreRpm: float = 0.0
    zScoreErrorRate: float = 0.0
    # Window
    windowStart: datetime = Field(default_factory=datetime.utcnow)
    windowEnd: datetime = Field(default_factory=datetime.utcnow)
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ─── Scan signal routing ─────────────────────────────────────────────────


class ScanSignals(BaseModel):
    """Routing signals that determine which collections to query."""
    has_infra_data: bool = False
    has_screenshot: bool = False
    has_traffic_anomaly: bool = False
    detected_language: str = "en"
    has_dark_web_indicators: bool = False
    has_qr_source: bool = False

    @property
    def needs_regional_search(self) -> bool:
        return self.detected_language != "en"

    @property
    def needs_visual_search(self) -> bool:
        return self.has_screenshot

    @property
    def needs_infra_search(self) -> bool:
        return self.has_infra_data

    @property
    def needs_behavior_search(self) -> bool:
        return self.has_traffic_anomaly
