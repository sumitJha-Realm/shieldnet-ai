"""Natural language narrative builder for embedding model input."""

from __future__ import annotations

from enricher.models import EnrichmentResult


def build_narrative(r: EnrichmentResult) -> str:
    """Generate a human-readable behavioral paragraph from enrichment data.

    This output is designed to be sent to an embedding API for vector generation.
    It fuses textual and non-textual signals into a single dense description.
    """
    s = r.structure
    d = r.dns
    w = r.whois
    h = r.hosting
    t = r.tls
    rd = r.redirects
    bi = r.brand_impersonation

    if not s:
        return f"Analyzing URL {r.url} — structure analysis unavailable."

    parts: list[str] = []

    # ── Opening ──────────────────────────────────────────────────────────
    parts.append(f"Analyzing URL {r.url}")

    # ── Domain registration ──────────────────────────────────────────────
    domain_info = f"Domain {s.domain}"
    if w.domain_age_days >= 0:
        domain_info += f" registered {w.domain_age_days} days ago"
    if w.registrar != "unknown":
        domain_info += f" via {w.registrar}"
    if w.whois_privacy:
        domain_info += " with WHOIS privacy enabled"
    if w.registration_country != "unknown":
        domain_info += f" in {w.registration_country}"
    parts.append(domain_info + ".")

    if w.expires_soon and w.days_until_expiry >= 0:
        parts.append(f"Domain expires in {w.days_until_expiry} days (disposable indicator).")

    # ── DNS ──────────────────────────────────────────────────────────────
    if d.resolves:
        dns_text = f"DNS resolves to {', '.join(d.a_records[:3])}"
        if h.country != "unknown":
            dns_text += f" in {h.country}"
        if h.hosting_type != "unknown":
            dns_text += f" on {h.hosting_type} hosting"
        if h.asn:
            dns_text += f" ASN AS{h.asn} {h.asn_org}"
        if not d.has_dnssec:
            dns_text += " with no DNSSEC"
        else:
            dns_text += " with DNSSEC enabled"
        parts.append(dns_text + ".")

        if d.reverse_dns and not d.reverse_dns_matches:
            parts.append(f"Reverse DNS mismatch: {d.reverse_dns}.")
        elif d.reverse_dns and d.reverse_dns_matches:
            parts.append(f"Reverse DNS matches: {d.reverse_dns}.")

        if d.a_record_count > 3:
            parts.append(f"Multiple A records ({d.a_record_count}) suggest CDN or load balancer.")
    else:
        parts.append(f"DNS resolution failed ({d.resolution_status}).")

    # ── Hosting flags ────────────────────────────────────────────────────
    if h.is_suspicious_asn:
        parts.append(f"WARNING: ASN AS{h.asn} ({h.asn_org}) is in suspicious/bulletproof ASN list.")
    if h.cloud_provider:
        parts.append(f"Hosted on {h.cloud_provider} cloud infrastructure.")

    # ── TLS ──────────────────────────────────────────────────────────────
    if t.has_tls:
        tls_text = f"TLS certificate is {t.cert_type}"
        if t.issuer != "unknown":
            issuer_short = t.issuer.split(",")[0] if "," in t.issuer else t.issuer
            tls_text += f" issued by {issuer_short}"
        if t.cert_age_days >= 0:
            tls_text += f", {t.cert_age_days} days old"
        parts.append(tls_text + ".")

        if t.is_recently_issued:
            parts.append("Certificate was issued less than 7 days ago (suspicious for established domains).")
        if not t.subject_matches_domain:
            parts.append("Certificate subject does NOT match the domain (possible man-in-the-middle).")
        if t.cert_type == "self-signed":
            parts.append("Self-signed certificate detected — not trusted by browsers.")
        if t.cert_type == "expired":
            parts.append("EXPIRED certificate — browsers will show security warning.")
    else:
        parts.append("No TLS certificate (plain HTTP) — all traffic is unencrypted.")

    # ── URL structure ────────────────────────────────────────────────────
    structure_parts: list[str] = []
    structure_parts.append(f"URL entropy {s.entropy}")
    if s.subdomain_depth > 0:
        structure_parts.append(f"subdomain depth {s.subdomain_depth}")
    if s.is_ip_address:
        structure_parts.append("domain is raw IP address")
    if s.suspicious_keywords:
        structure_parts.append(f"suspicious keywords: {', '.join(s.suspicious_keywords)}")
    if s.has_url_encoding:
        structure_parts.append("uses URL encoding")
    if s.excessive_hyphens:
        structure_parts.append(f"excessive hyphens in domain ({s.hyphen_count})")
    if s.special_char_count > 0:
        structure_parts.append(f"{s.special_char_count} special chars in path")
    if structure_parts:
        parts.append(", ".join(structure_parts) + ".")

    # ── Brand impersonation ──────────────────────────────────────────────
    if bi and bi.is_exact_match:
        parts.append(
            f"Domain matches known government domain {bi.known_domain} ({bi.closest_brand})."
        )
    elif bi and 0 < bi.edit_distance <= 3:
        parts.append(
            f"Brand impersonation detected: edit distance {bi.edit_distance} "
            f"from known government domain {bi.known_domain} ({bi.closest_brand})."
        )

    # ── Redirects ────────────────────────────────────────────────────────
    if rd.total_hops > 0:
        redirect_text = f"Redirect chain: {rd.total_hops} hop(s)"
        if rd.final_domain_differs:
            final_domain = rd.final_url.split("/")[2] if "/" in rd.final_url else rd.final_url
            redirect_text += f", final destination on different domain ({final_domain})"
        if rd.passes_through_shortener:
            redirect_text += f", passes through URL shortener(s): {', '.join(rd.shorteners_used)}"
        if rd.excessive_redirects:
            redirect_text += " (EXCESSIVE — possible evasion)"
        parts.append(redirect_text + ".")

    return " ".join(parts)
