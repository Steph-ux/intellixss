"""Header reflection XSS (v3 self-contained plugin)."""

from __future__ import annotations

import hashlib
import time
from typing import List, Optional

from intellixss.analysis.context import detect_context
from intellixss.analysis.reflection import is_payload_effective
from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding
from intellixss.payloads.generator import generate_payloads
from intellixss.verify.check import evaluate_response

HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Host",
]


async def scan_header_xss(
    client: HttpClient,
    url: str,
    *,
    browser=None,
    max_headers: int = 5,
    max_payloads: int = 8,
    log=None,
) -> List[XSSFinding]:
    """Probe reflected headers → context payloads → optional browser confirm."""
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []

    for header in HEADERS[:max_headers]:
        canary = f"hx{hashlib.md5(f'{header}{time.time()}'.encode()).hexdigest()[:8]}"
        st, body, hdrs, fin = await client.request(
            "GET", url, headers={header: canary}
        )
        if st == 0 or not body or canary not in body:
            continue
        log(f"    [header] reflection in {header}", "info")
        ctx = detect_context(body, canary)
        payloads = generate_payloads(ctx, limit=max_payloads)
        for payload in payloads:
            st2, body2, hdrs2, fin2 = await client.request(
                "GET", url, headers={header: payload}
            )
            out = evaluate_response(
                url=fin2 or url,
                param=f"header:{header}",
                method="GET",
                payload=payload,
                status=st2,
                body=body2 or "",
                headers=hdrs2,
                context=ctx,
            )
            if not out.success or not out.finding:
                continue
            finding = out.finding
            finding.vulnerability_type = "header_reflected"
            # Browser confirm via route interception is hard for headers;
            # mark reflection-only unless body still executable and browser navigates same URL without header.
            # For header XSS, browser can't inject custom headers without route — keep reflection.
            findings.append(finding)
            log(
                f"    [VULN] header {header} context={ctx.value} payload={payload[:50]!r}",
                "vuln",
            )
            break
    return findings
