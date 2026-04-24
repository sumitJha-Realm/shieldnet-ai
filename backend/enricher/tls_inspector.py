"""TLS certificate analysis — async live inspection."""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone

from enricher.config import TLS_TIMEOUT
from enricher.models import TLSResult

logger = logging.getLogger(__name__)

# Let's Encrypt issuer OIDs / names
_FREE_CA = ("let's encrypt", "letsencrypt", "zerossl", "buypass", "ssl.com free")
_SELF_SIGNED_MARKER = "self-signed"


def _sync_tls_inspect(hostname: str, port: int = 443) -> TLSResult:
    """Blocking TLS handshake + certificate extraction."""
    result = TLSResult()
    ctx = ssl.create_default_context()
    # Allow inspection of bad certs so we can report them
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                der = ssock.getpeercert(binary_form=True)

        if not cert and der:
            # CERT_NONE mode may only give binary; decode manually
            import ssl as _ssl
            cert = _ssl._ssl._test_decode_cert(der)  # type: ignore[attr-defined]

        if not cert:
            result.has_tls = True
            result.cert_type = "unknown"
            return result

        result.has_tls = True

        # ── Issuer ───────────────────────────────────────────────────
        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_name, attr_val in rdn:
                issuer_parts.append(f"{attr_name}={attr_val}")
        result.issuer = ", ".join(issuer_parts) or "unknown"

        # ── Subject ──────────────────────────────────────────────────
        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_name, attr_val in rdn:
                subject_parts.append(f"{attr_name}={attr_val}")
        result.subject = ", ".join(subject_parts) or "unknown"

        # ── Validity dates ───────────────────────────────────────────
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        now = datetime.now(timezone.utc)
        if not_before:
            vf = _parse_cert_date(not_before)
            if vf:
                result.valid_from = vf.isoformat()
                result.cert_age_days = (now - vf).days
                result.is_recently_issued = result.cert_age_days < 7
        if not_after:
            vt = _parse_cert_date(not_after)
            if vt:
                result.valid_to = vt.isoformat()
                result.days_until_expiry = (vt - now).days

        # ── Cert type classification ─────────────────────────────────
        issuer_lower = result.issuer.lower()
        if result.issuer == result.subject or _SELF_SIGNED_MARKER in issuer_lower:
            result.cert_type = "self-signed"
        elif result.days_until_expiry < 0:
            result.cert_type = "expired"
        elif any(ca in issuer_lower for ca in _FREE_CA):
            result.cert_type = "free"
        elif "extended validation" in issuer_lower or "ev " in issuer_lower:
            result.cert_type = "EV"
        elif "organization" in issuer_lower:
            result.cert_type = "OV"
        else:
            result.cert_type = "DV"

        # ── Subject match ────────────────────────────────────────────
        san = cert.get("subjectAltName", ())
        san_domains = [v for t, v in san if t == "DNS"]
        cn_domains = [v for rdn in cert.get("subject", ()) for _, v in rdn]
        all_cert_domains = [d.lower() for d in san_domains + cn_domains]
        result.subject_matches_domain = any(
            hostname.lower() == d or hostname.lower().endswith("." + d.lstrip("*."))
            for d in all_cert_domains
        )

    except (socket.timeout, ConnectionRefusedError, OSError):
        result.cert_type = "missing"
    except Exception as exc:
        logger.debug("TLS inspection failed for %s: %s", hostname, exc)
        result.cert_type = "missing"

    return result


def _parse_cert_date(date_str: str) -> datetime | None:
    """Parse OpenSSL-style certificate date strings."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z",
                "%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


async def inspect_tls(hostname: str, port: int = 443) -> TLSResult:
    """Async wrapper around blocking TLS inspection."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_tls_inspect, hostname, port),
            timeout=TLS_TIMEOUT + 2,
        )
    except asyncio.TimeoutError:
        logger.warning("TLS inspection timeout for %s", hostname)
        return TLSResult(cert_type="timeout")
    except Exception as exc:
        logger.warning("TLS inspection error for %s: %s", hostname, exc)
        return TLSResult()
