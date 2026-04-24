from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class ThreatClassification(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    C2 = "c2"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"


class DNSStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PARKED = "parked"


class URLStatus(str, Enum):
    BLOCKED = "blocked"
    ALLOWED = "allowed"
    UNDER_REVIEW = "under_review"


class HostingFlags(BaseModel):
    isSharedHosting: bool = False
    isCloudHosted: bool = False
    hostingProvider: str = "unknown"
    geoLocation: str = "unknown"
    sslValid: bool = False
    domainAgeDays: int = 0


class URLStructure(BaseModel):
    pathDepth: int = 0
    hasIpAddress: bool = False
    hasSuspiciousTld: bool = False
    entropyScore: float = 0.0
    containsEncodedChars: bool = False
    subdomainCount: int = 0


class URLRecord(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    url: str
    domain: str
    submissionDate: datetime = Field(default_factory=datetime.utcnow)
    source: str = "automated_crawler"
    dnsStatus: DNSStatus = DNSStatus.ACTIVE
    hostingFlags: HostingFlags = Field(default_factory=HostingFlags)
    urlStructure: URLStructure = Field(default_factory=URLStructure)
    threatClassification: ThreatClassification = ThreatClassification.SUSPICIOUS
    riskScore: float = 0.0
    status: URLStatus = URLStatus.UNDER_REVIEW
    reviewedBy: str = "system_ai"
    summaryText: str = ""
    embedding: Optional[list[float]] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        json_encoders = {datetime: lambda v: v.isoformat()}


class ThreatLog(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    urlId: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str = "flagged"
    userDepartment: str = ""
    userType: str = "gov_employee"
    deviceType: str = "desktop"
    ipRegion: str = ""
    aiConfidence: float = 0.0

    class Config:
        populate_by_name = True


class ThreatIntelFeed(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    feedName: str
    url: str
    reportedDate: datetime = Field(default_factory=datetime.utcnow)
    threatType: str = "phishing"
    description: str = ""
    embedding: Optional[list[float]] = None

    class Config:
        populate_by_name = True


class URLScanRequest(BaseModel):
    url: str


class URLScanResponse(BaseModel):
    urlRecord: URLRecord
    similarThreats: list[dict] = []
    recommendedAction: str = "review"
    riskLevel: str = "medium"


class StatusUpdateRequest(BaseModel):
    status: URLStatus


class DashboardStats(BaseModel):
    totalScanned: int = 0
    blockedToday: int = 0
    underReview: int = 0
    activeThreats: int = 0
    riskDistribution: dict = {}
    departmentStats: list[dict] = []
