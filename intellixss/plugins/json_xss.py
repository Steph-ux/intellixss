"""JSON body XSS scanner (REST APIs)."""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from intellixss.analysis.reflection import is_payload_effective
from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding
from intellixss.payloads.generator import make_marker, mark_call

_COMMON_FIELDS = [
    "query", "search", "q", "message", "comment", "body", "content",
    "text", "name", "title", "description", "input", "value", "data",
]


def json_payloads(marker: str) -> List[str]:
    """Body values for *marker*, so the browser can attribute a dialog to them."""
    a = mark_call(marker)
    tick = mark_call(marker, "tick")
    return [
        f"<img src=x onerror={a}>",
        f"<svg/onload={a}>",
        f'"><img src=x onerror={a}>',
        f"<details open ontoggle={a}>",
        f"\\u003cimg src=x onerror={a}\\u003e",
        f"<svg/onload={tick}>",
    ]

_FETCH_RE = [
    re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""axios\.(?:post|put|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I),
    re.compile(r"""['"`](/api/[^'"`]+)['"`]""", re.I),
]

_API_GUESSES = [
    "/api", "/api/v1", "/api/v2", "/api/search", "/api/comments",
    "/api/message", "/api/feedback", "/rest", "/v1/search",
]


def discover_json_endpoints(base_url: str, html: str = "") -> List[str]:
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    found: List[str] = []
    seen: Set[str] = set()

    def add(path: str) -> None:
        if not path or path.startswith("data:"):
            return
        full = urljoin(origin + "/", path.lstrip("/")) if path.startswith("/") else urljoin(base_url, path)
        if urlparse(full).netloc != urlparse(base_url).netloc:
            return
        if full not in seen:
            seen.add(full)
            found.append(full)

    for rx in _FETCH_RE:
        for m in rx.finditer(html or ""):
            add(m.group(1))
    for g in _API_GUESSES:
        add(g)
    return found[:20]


async def scan_json_xss(
    client: HttpClient,
    base_url: str,
    *,
    html: str = "",
    browser=None,
    max_endpoints: int = 8,
    max_fields: int = 6,
    max_payloads: int = 5,
    log=None,
) -> List[XSSFinding]:
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []
    endpoints = discover_json_endpoints(base_url, html)[:max_endpoints]
    log(f"    [json] probing {len(endpoints)} endpoint(s)", "info")

    # One marker per run: every payload below names it, and the browser is
    # asked to prove that marker and no other.
    marker = make_marker(hashlib.md5(f"{base_url}{time.time()}".encode()).hexdigest()[:8])
    payloads = json_payloads(marker)

    for ep in endpoints:
        for field in _COMMON_FIELDS[:max_fields]:
            canary = f"jx{hashlib.md5(f'{ep}{field}{time.time()}'.encode()).hexdigest()[:8]}"
            st, body, hdrs, fin = await client.inject_json(ep, field, canary)
            if st == 0 or not body:
                continue
            if canary not in body:
                continue
            log(f"    [json] reflection {ep[:50]} field={field}", "info")
            for payload in payloads[:max_payloads]:
                st2, body2, hdrs2, fin2 = await client.inject_json(ep, field, payload)
                if st2 == 0 or not body2:
                    continue
                ok, tag = is_payload_effective(body2, payload, "html_text")
                # also accept raw payload in JSON that will be rendered later
                if not ok and payload not in body2 and payload.replace("<", "\\u003c") not in body2:
                    # unicode payload form
                    if "\\u003c" in payload and payload not in body2:
                        continue
                    if payload not in body2:
                        continue
                    tag = "json_raw_reflection"
                    ok = True
                if not ok:
                    continue
                finding = XSSFinding(
                    url=fin2 or ep,
                    parameter=f"json:{field}",
                    method="POST",
                    context=InjectionContext.JSON_VALUE,
                    payload=payload,
                    evidence=f"json_body_xss:{tag}",
                    vulnerability_type="json_body",
                    confidence=0.8,
                    browser_confirmed=False,
                )
                # Browser confirm only if endpoint returns HTML
                ctype = (hdrs2 or {}).get("Content-Type", "")
                if browser and browser.available and "html" in ctype.lower():
                    br = await browser.confirm(finding.url, payload=payload, marker=marker)
                    if br.confirmed:
                        finding.browser_confirmed = True
                        finding.confidence = 0.95
                        finding.evidence += f" | browser:{br.detail}"
                findings.append(finding)
                log(
                    f"    [VULN] JSON XSS {field} @ {ep[:40]} browser={finding.browser_confirmed}",
                    "vuln",
                )
                return findings  # one solid hit enough per scan pass
    return findings
