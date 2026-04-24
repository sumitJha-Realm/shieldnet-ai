"""Redirect chain analysis — follow HTTP redirects and inspect each hop."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from enricher.config import HTTP_TIMEOUT, MAX_REDIRECTS, URL_SHORTENERS
from enricher.models import RedirectHop, RedirectResult

logger = logging.getLogger(__name__)


async def follow_redirects(url: str) -> RedirectResult:
    """Follow HTTP redirects manually and record each hop."""
    result = RedirectResult(final_url=url)
    hops: list[RedirectHop] = []
    current_url = url
    original_domain = urlparse(url).hostname or ""

    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
            verify=False,
        ) as client:
            for _ in range(MAX_REDIRECTS):
                try:
                    resp = await client.get(current_url)
                except httpx.ConnectError:
                    break
                except httpx.TimeoutException:
                    break
                except Exception:
                    break

                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Handle relative redirects
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"

                    hops.append(RedirectHop(
                        url=current_url,
                        status_code=resp.status_code,
                        redirect_type=str(resp.status_code),
                    ))

                    # Check if this hop goes through a URL shortener
                    hop_domain = (urlparse(current_url).hostname or "").lower()
                    if hop_domain in URL_SHORTENERS:
                        result.passes_through_shortener = True
                        if hop_domain not in result.shorteners_used:
                            result.shorteners_used.append(hop_domain)

                    current_url = location
                else:
                    # Final destination (non-redirect response)
                    break

    except Exception as exc:
        logger.debug("Redirect chain analysis failed for %s: %s", url, exc)

    result.hops = hops
    result.total_hops = len(hops)
    result.final_url = current_url
    result.excessive_redirects = len(hops) > 3

    final_domain = (urlparse(current_url).hostname or "").lower()
    result.final_domain_differs = final_domain != original_domain.lower()

    return result
