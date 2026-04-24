"""Pydantic data models for all enrichment outputs."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── URL Structure ────────────────────────────────────────────────────────
class URLStructure(BaseModel):
    scheme: str
    domain: str
    subdomain: str = ""
    path: str = "/"
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    fragment: str = ""
    url_length: int = 0
    entropy: float = 0.0
    subdomain_depth: int = 0
    is_ip_address: bool = False
    special_char_count: int = 0
    has_url_encoding: bool = False
    suspicious_keywords: list[str] = Field(default_factory=list)
    excessive_hyphens: bool = False
    hyphen_count: int = 0


class BrandImpersonation(BaseModel):
    closest_brand: str = ""
    known_domain: str = ""
    edit_distance: int = -1
    is_exact_match: bool = False


# ── DNS ──────────────────────────────────────────────────────────────────
class DNSResult(BaseModel):
    resolves: bool = False
    resolution_status: str = "unknown"         # success / nxdomain / servfail / timeout
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    cname_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    a_record_count: int = 0
    cname_chain_depth: int = 0
    has_dnssec: bool = False
    reverse_dns: str = ""
    reverse_dns_matches: bool = False
    ttl: int = 0


# ── WHOIS ────────────────────────────────────────────────────────────────
class WHOISResult(BaseModel):
    domain_age_days: int = -1
    registrar: str = "unknown"
    whois_privacy: bool = False
    registration_country: str = "unknown"
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    days_until_expiry: int = -1
    expires_soon: bool = False                  # < 30 days


# ── Hosting / GeoIP ─────────────────────────────────────────────────────
class HostingResult(BaseModel):
    ip: str = ""
    country: str = "unknown"
    country_code: str = ""
    city: str = "unknown"
    isp: str = "unknown"
    asn: int = 0
    asn_org: str = "unknown"
    hosting_type: str = "unknown"               # dedicated/shared/cloud/cdn/bulletproof
    cloud_provider: str = ""
    is_suspicious_asn: bool = False
    in_blocklist: bool = False


# ── TLS Certificate ─────────────────────────────────────────────────────
class TLSResult(BaseModel):
    has_tls: bool = False
    issuer: str = "unknown"
    subject: str = "unknown"
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_until_expiry: int = -1
    cert_type: str = "unknown"                  # EV/OV/DV/free/self-signed/expired/missing
    cert_age_days: int = -1
    is_recently_issued: bool = False            # < 7 days
    subject_matches_domain: bool = False


# ── Redirect Chain ───────────────────────────────────────────────────────
class RedirectHop(BaseModel):
    url: str
    status_code: int
    redirect_type: str = ""                     # 301/302/307/meta


class RedirectResult(BaseModel):
    total_hops: int = 0
    hops: list[RedirectHop] = Field(default_factory=list)
    final_url: str = ""
    final_domain_differs: bool = False
    excessive_redirects: bool = False
    passes_through_shortener: bool = False
    shorteners_used: list[str] = Field(default_factory=list)


# ── Full enrichment output ───────────────────────────────────────────────
class EnrichmentResult(BaseModel):
    url: str
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    structure: Optional[URLStructure] = None
    dns: DNSResult = Field(default_factory=DNSResult)
    whois: WHOISResult = Field(default_factory=WHOISResult)
    hosting: HostingResult = Field(default_factory=HostingResult)
    tls: TLSResult = Field(default_factory=TLSResult)
    redirects: RedirectResult = Field(default_factory=RedirectResult)
    brand_impersonation: Optional[BrandImpersonation] = None
    narrative: str = ""
    enrichment_time_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)
