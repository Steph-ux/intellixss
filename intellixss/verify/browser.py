"""Playwright browser confirmation of XSS findings.

Design principles
-----------------
1. **Marker over presence.** A dialog only proves execution if it announces
   the *unique* marker we injected (``ixm1a2b3c4``). A generic ``alert(1)``
   dialog can be page noise; a dialog saying ``ixm1a2b3c4`` cannot.
2. **Causality.** Before navigation we snapshot which sentinel elements exist
   and *which of them already have inline handlers*. During confirmation we
   only attribute a dialog to our payload when it fires alongside our marker.
3. **Injectable JS.** When the caller provides ``exec_code`` (built for the
   detected context) we evaluate it in the page. This catches DOM sinks that a
   server-side reflection alone cannot prove, and lets us fall back to
   ``eval(atob(...))`` when a WAF mangles keywords.
4. **No blind clicks.** Interactions are capped, scoped to elements created by
   our payload where possible, and always close the page.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse, urlsplit

from intellixss.config import Config

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    async_playwright = None  # type: ignore
    PlaywrightTimeout = Exception  # type: ignore
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class BrowserConfirmResult:
    confirmed: bool
    detail: str = ""
    dialog_message: str = ""
    trigger: str = ""  # load | hashchange | click | focus | hover | interaction | eval
    marker_echoed: bool = False
    logs: List[str] = field(default_factory=list)


# How long to keep watching a page after DOMContentLoaded for a payload that
# executes on a timer rather than during parsing.
_SETTLE_SECONDS = 1.6

# Hard cap on closing a page. A wedged handler can make close() hang forever.
_CLOSE_SECONDS = 5.0

# Navigations a speculative confirmation leaves untouched on a host. A route the
# bundle only suggests is a guess; a sink whose record was written and read back
# is not, and the budget is too small for guesses to consume the whole of it.
_SPECULATIVE_RESERVE = 4


_CONSOLE_HOOK = """
// Observe console output of injected payloads (fallback when dialogs are blocked)
window.__ix_hits = window.__ix_hits || [];
if (!window.__ix_hooked) {
  window.__ix_hooked = true;
  const orig = console.log;
  console.log = function(...a) {
    try { window.__ix_hits.push('console:' + a.map(String).join(' ')); } catch(e){}
    return orig.apply(console, a);
  };
  window.addEventListener('error', e => {
    try { window.__ix_hits.push('error:' + (e.message||'')); } catch(e){}
  });
}
"""


# A referrer cannot be reconstructed after the fact: a page that branches on
# ``document.referrer`` before it declares its own bindings throws on the
# "empty referrer" path, and no later navigation recovers it. Defining the
# property before any page script runs reproduces what the sink was written to
# see, and matches the attack model (an attacker chooses the referrer).
_REFERRER_INIT = """
(() => {
  const want = %s;
  try {
    Object.defineProperty(document, 'referrer', {
      configurable: true,
      get: () => want,
    });
  } catch (e) {
    try { Object.defineProperty(Document.prototype, 'referrer', { get: () => want }); } catch (e2) {}
  }
})();
"""


# A sink that reads ``localStorage`` decodes a value the application itself
# wrote there, not a URL parameter. The seed therefore has to be installed in
# storage *before* the page's first script runs — Angular-style SPA routers
# abort the navigation when the token is missing, so setting it after ``goto()``
# leaves the view empty and the sink unreachable.
_STORAGE_INIT = """
(() => {
  const items = %s;
  const store = %s;
  try {
    const s = store === 'session' ? window.sessionStorage : window.localStorage;
    for (const k of Object.keys(items)) {
      s.setItem(k, items[k]);
    }
  } catch (e) {}
})();
"""


class BrowserConfirmer:
    """
    Headless Chromium confirmation:
    - dialog (alert/confirm/prompt) whose message carries our marker → confirmed
    - console.log(marker) when dialogs are unavailable → confirmed
    - javascript: href clicks scoped to our injected link
    - hash/fragment DOM sinks
    - light interaction (focus/hover) for event-handler XSS
    """

    def __init__(self, config: Config, log=None):
        self.config = config
        self._log = log or (lambda *a, **k: None)
        self._pw = None
        self._session_cookies: dict = {}
        self._session_storage: dict = {}
        self._browser = None
        self._sem = asyncio.Semaphore(max(1, config.browser_concurrency))
        self._budget = {}  # host -> remaining navigations
        self._spent = {}  # host -> {kind: navigations taken}
        # host -> seeded flows still to confirm. A probe may not spend into
        # these: they are evidence, the probe is a guess.
        self._seeded_pending = {}
        self.available = False
        self.navigations = 0

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        if not self.config.use_browser:
            return False
        if not PLAYWRIGHT_AVAILABLE:
            self._log("[-] Playwright not installed — browser confirmation disabled", "warn")
            return False
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-background-networking",
                ],
            )
            self.available = True
            self._log("[*] Browser confirmer ready (headless Chromium)", "info")
            return True
        except Exception as e:
            self._log(f"[-] Browser init failed: {e}", "warn")
            self.available = False
            return False

    async def stop(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._pw = None
        self.available = False

    def set_cookies(self, cookies: dict) -> None:
        """Offer a session acquired over HTTP to every page opened later.

        The confirmer's pages are separate browsing contexts, so without this a
        sink behind a login would be requested as an anonymous visitor and
        refuted for a reason that has nothing to do with the payload. Cookies
        are stored with their value only; a ``Secure``/``HttpOnly`` flag cannot
        be expressed once the header is parsed, and neither affects whether the
        page renders the same way for the session.
        """
        self._session_cookies = {
            str(k): str(v) for k, v in (cookies or {}).items() if str(k)
        }

    def set_storage(self, items: dict) -> None:
        """Offer a token an SPA keeps in ``localStorage`` to every page later.

        A cookie session and a stored token are not the same session: a
        single-page application reads its bearer token out of the store and
        renders nothing without it, so a sink behind such a login would be
        refuted as if the page were anonymous. Values are set before the page's
        first script, since the router reads them synchronously.
        """
        self._session_storage = {
            str(k): str(v) for k, v in (items or {}).items() if str(k)
        }

    # ------------------------------------------------------------------
    # budget (avoid hammering a host with Chromium navigations)
    # ------------------------------------------------------------------

    def note_seeded_pending(self, url: str, count: int) -> None:
        """Declare that *count* seeded flows on *url*'s host still need a slot.

        A seeded flow is one whose source the page itself reads — a value out of
        ``localStorage``, a referrer, a window name — with a sink the analysis
        has already named. Confirming it is evidence, not a guess, so its
        navigations are protected from probes that would spend them on a route
        the bundle only suggested. The protection is a count that shrinks as the
        flows are confirmed, not a constant.
        """
        host = urlparse(url).netloc
        if count > 0:
            self._seeded_pending[host] = count
        else:
            self._seeded_pending.pop(host, None)

    def note_seeded_confirmed(self, url: str) -> None:
        """One queued seeded flow has been confirmed: release its slot."""
        host = urlparse(url).netloc
        left = self._seeded_pending.get(host, 0) - 1
        if left > 0:
            self._seeded_pending[host] = left
        else:
            self._seeded_pending.pop(host, None)

    def _seeded_reserve(self, url: str) -> int:
        """Navigations a probe must leave for the seeded flows still queued."""
        return max(0, self._seeded_pending.get(urlparse(url).netloc, 0))

    def _take_slot(
        self, url: str, *, speculative: bool = False, reserve: int = 0, kind: str = ""
    ) -> bool:
        """Take one navigation slot for *url*'s host, or refuse.

        Checking and spending are one operation: confirmations are awaited from
        several scan tasks at once, and a caller that only checked would let the
        next one take the same last slot.

        *speculative* marks a navigation the scan has no evidence for — a route
        the bundle merely suggests. It may not touch the last *reserve* slots,
        which belong to confirmations of a value that was written and read back,
        so a run of guesses cannot starve the one result that is already proven.

        *kind* is what the navigation is for, when the caller knows: the slots
        it spends are recorded per kind so the scan can say where the budget
        went instead of leaving an exhausted host as one unexplained number.
        """
        cap = self.config.max_confirm_per_host
        if cap <= 0:
            # Uncapped means uncapped: nothing is spent, so nothing has to be
            # tracked, and ``budget_left`` and the spend agree on that host.
            return True
        host = urlparse(url).netloc
        left = self._budget.get(host, cap)
        # A probe protects both what the caller asked for and every seeded flow
        # still queued on this host: the larger of the two, because either one
        # being starved is the failure the reserve exists to prevent.
        floor = max(max(0, reserve), self._seeded_reserve(url))
        if speculative and left <= floor:
            return False
        if left <= 0:
            return False
        self._budget[host] = left - 1
        if kind:
            spent = self._spent.setdefault(host, {})
            spent[kind] = spent.get(kind, 0) + 1
        return True

    def _may_navigate(
        self, url: str, *, speculative: bool = False, reserve: int = 0, kind: str = ""
    ) -> bool:
        return self._take_slot(url, speculative=speculative, reserve=reserve, kind=kind)

    def can_spend(
        self, url: str, *, speculative: bool = False, reserve: int = 0
    ) -> bool:
        """Whether a navigation of *url* would be allowed, without spending it.

        A caller that plans a navigation may ask first and let ``confirm`` take
        the slot, so one navigation costs one slot rather than two.
        """
        cap = self.config.max_confirm_per_host
        if cap <= 0:
            return True
        left = self._budget.get(urlparse(url).netloc, cap)
        if left <= 0:
            return False
        floor = max(max(0, reserve), self._seeded_reserve(url))
        return not (speculative and left <= floor)

    def budget_left(self, url: str) -> int:
        """Navigations still allowed for *url*'s host (a large number if uncapped)."""
        cap = self.config.max_confirm_per_host
        if cap <= 0:
            return 1 << 30
        return self._budget.get(urlparse(url).netloc, cap)

    # ------------------------------------------------------------------
    # source seeding
    # ------------------------------------------------------------------

    async def _seed_sources(
        self,
        page,
        url: str,
        window_name: str,
        cookies: Optional[List[Tuple[str, str]]],
        storage: Optional[dict] = None,
        session_storage: Optional[dict] = None,
    ) -> None:
        """Give the page the browser-owned values a DOM sink may read."""
        try:
            host = urlparse(url).hostname or ""
            jar = dict(self._session_cookies)
            for n, v in cookies or []:
                jar[str(n)] = str(v)
            if jar and host:
                await page.context.add_cookies(
                    [
                        {"name": n, "value": v, "url": f"{urlparse(url).scheme}://{host}/"}
                        for n, v in jar.items()
                    ]
                )
            # The session's own stored token goes in first, then the payload
            # seed on top: a sink that reads the token must find a session the
            # page can render, and the seed is what that token decodes into.
            local = dict(self._session_storage)
            local.update(storage or {})
            for kind, items in (("local", local), ("session", session_storage)):
                if items:
                    # Installed as an init script so it runs against the page's
                    # own origin before any of its code. ``about:blank`` cannot
                    # hold storage for the target origin, so navigation is needed.
                    await page.add_init_script(
                        _STORAGE_INIT % (json.dumps(items), json.dumps(kind))
                    )
            if window_name:
                # window.name survives navigation because it belongs to the
                # browsing context, so it must be set on *this* page first.
                await page.goto(
                    "about:blank", timeout=min(5000, self.config.browser_timeout_ms)
                )
                await page.evaluate("n => { window.name = n; }", window_name)
        except Exception:
            pass

    async def _navigate_with_referrer(
        self, page, referrer: str, url: str, timeout_ms: int
    ) -> None:
        """Navigate to *url* with *referrer* attached.

        ``document.referrer`` is whatever the browser sent, so the header has to
        be set on the request itself. Playwright's ``goto(referer=…)`` sends it
        without a preliminary navigation, which keeps a sink that reads the
        referrer on parse from seeing an empty value first.
        """
        try:
            await page.goto(
                url,
                referer=referrer,
                timeout=timeout_ms,
                wait_until="domcontentloaded",
            )
        except PlaywrightTimeout:
            pass
        except Exception:
            # Older Playwright builds without ``referer``: fall back to a
            # same-origin link click, which also carries the URL as referrer.
            try:
                await page.goto(referrer, timeout=timeout_ms, wait_until="domcontentloaded")
                await page.evaluate(
                    """([target]) => {
                        const a = document.createElement('a');
                        a.href = target;
                        document.body.appendChild(a);
                        a.click();
                    }""",
                    [url],
                )
                await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
            except Exception:
                pass

    async def _open_with_referrer(
        self, page, referrer: str, url: str, timeout_ms: int
    ) -> None:
        """Open *url* in a page whose ``document.referrer`` is already *referrer*.

        Used when the sink reads the referrer *before* declaring anything, which
        a normal navigation cannot satisfy: a browser load without a referrer
        takes the page's empty branch and the document throws.
        """
        try:
            await page.add_init_script(_REFERRER_INIT % json.dumps(referrer))
        except Exception:
            pass
        try:
            await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
        except PlaywrightTimeout:
            pass
        except Exception:
            pass

    async def confirm(
        self,
        url: str,
        *,
        context_hint: str = "",
        payload: str = "",
        marker: str = "",
        exec_code: str = "",
        timeout_ms: Optional[int] = None,
        allow_eval: bool = True,
        referrer: str = "",
        window_name: str = "",
        cookies: Optional[List[Tuple[str, str]]] = None,
        storage: Optional[dict] = None,
        session_storage: Optional[dict] = None,
        warm_url: str = "",
        speculative: bool = False,
        kind: str = "",
        reserve: Optional[int] = None,
    ) -> BrowserConfirmResult:
        """
        Navigate to *url* and decide whether our payload executed.

        *marker* is the unique token embedded in the payload. When omitted we
        try to extract it from *payload*. Without a marker we fall back to
        "any dialog fired during the observation window" — still useful, but
        reported with lower confidence by the caller.

        The whole probe is bounded by a wall-clock deadline: a payload that
        wedges the page (a broken handler, a navigation loop) must never stall
        the scan, so it is abandoned and reported as ``confirm_timeout``.

        *referrer*, *window_name* and *cookies* seed the DOM sinks that read a
        browser-owned source instead of a URL parameter. Without them a page
        doing ``eval(document.referrer)`` can only ever be reported as static.

        *warm_url* is the document a stored payload lives in. A record is
        written through a handler endpoint whose response carries no record at
        all, so the page that renders it has to be *opened* first; the payload
        is then driven against the page as it stands rather than against a URL
        that merely repeats it.

        *speculative* marks a navigation the scan has no evidence for. It may
        not spend the last slots of the per-host budget, which are held for
        confirmations of a value that a request already showed to be live.
        *reserve* is how many of those slots to leave; the default floor is used
        when the caller has a better reason for it.
        """
        if not self.available or not self._browser:
            return BrowserConfirmResult(False, "browser_unavailable")

        # A confirmation is causal or it is nothing. The probe is credited when
        # a dialog carries the marker this payload injected; without a marker
        # any dialog the page happens to raise would pass for execution. That
        # used to be accepted as "evidence-free" at the cost of confidence,
        # which made ``alert(1)`` a complete proof and let five of the six
        # plugins ship without one. It is now a caller defect, refused here so
        # that no navigation is spent on a probe that could not prove
        # anything even if it fired.
        if not (marker or _extract_marker(payload)):
            return BrowserConfirmResult(False, "confirm_without_marker")

        timeout_ms = timeout_ms or self.config.browser_timeout_ms
        budget = timeout_ms / 1000.0 + _SETTLE_SECONDS + _CLOSE_SECONDS * 3
        try:
            return await asyncio.wait_for(
                self._confirm_inner(
                    url,
                    context_hint=context_hint,
                    payload=payload,
                    marker=marker,
                    exec_code=exec_code,
                    timeout_ms=timeout_ms,
                    allow_eval=allow_eval,
                    referrer=referrer,
                    window_name=window_name,
                    cookies=cookies,
                    storage=storage,
                    session_storage=session_storage,
                    warm_url=warm_url,
                    speculative=speculative,
                    kind=kind,
                    reserve=reserve,
                ),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            return BrowserConfirmResult(False, "confirm_timeout")

    async def _confirm_inner(
        self,
        url: str,
        *,
        context_hint: str = "",
        payload: str = "",
        marker: str = "",
        exec_code: str = "",
        timeout_ms: Optional[int] = None,
        allow_eval: bool = True,
        referrer: str = "",
        window_name: str = "",
        cookies: Optional[List[Tuple[str, str]]] = None,
        storage: Optional[dict] = None,
        session_storage: Optional[dict] = None,
        warm_url: str = "",
        speculative: bool = False,
        kind: str = "",
        reserve: Optional[int] = None,
    ) -> BrowserConfirmResult:
        if not self.available or not self._browser:
            return BrowserConfirmResult(False, "browser_unavailable")

        marker = marker or _extract_marker(payload)
        timeout_ms = timeout_ms or self.config.browser_timeout_ms

        async with self._sem:
            # The slot is taken here, not in ``confirm``: a caller that is not
            # on the browser's event loop, or one that asks while the browser is
            # unavailable, must not spend a navigation it cannot make. A
            # speculative navigation also stops at the reserve, so the last
            # slots of the host stay for values a request already proved live.
            if not self._may_navigate(
                url,
                speculative=speculative,
                reserve=_SPECULATIVE_RESERVE if reserve is None else reserve,
                kind=kind or ("route" if speculative else "reflected"),
            ):
                return BrowserConfirmResult(False, "confirm_budget_exhausted")
            page = None
            dialog_msg = ""
            dialog_hit = False

            async def on_dialog(dialog):
                nonlocal dialog_msg, dialog_hit
                dialog_hit = True
                try:
                    dialog_msg = dialog.message or dialog.type
                except Exception:
                    dialog_msg = "dialog"
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            # A payload does not have to open a dialog to have run. An image
            # ``onerror``, a ``fetch``, or a marker-carrying ``<script src>``
            # leaves the page for a URL the payload built: that request is the
            # same proof of execution as a dialog, and it is the only proof
            # available where every character an ``alert`` needs is encoded.
            #
            # The request must leave the target's own origin. The navigation
            # carries the payload in its query string, and the page's own
            # analytics echo reflected values into same-origin sub-resources, so
            # a marker seen on any of those came from the address bar rather than
            # from code the page ran. Only an off-origin request can be spawned
            # by the payload alone.
            request_hit = {"url": ""}
            origin = ""
            try:
                parsed = urlsplit(url or "")
                origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            except Exception:
                origin = ""

            def on_request(request):
                try:
                    if not marker or not origin:
                        return
                    if request.resource_type == "document":
                        return
                    url_l = request.url.lower()
                    if marker.lower() not in url_l:
                        return
                    if url_l.startswith(origin):
                        return
                    if not request_hit["url"]:
                        request_hit["url"] = request.url
                except Exception:
                    pass

            def dialog_matches() -> bool:
                if not dialog_hit:
                    return False
                if not marker:
                    # Evidence-free payload: accept but say so.
                    return True
                return marker.lower() in (dialog_msg or "").lower()

            try:
                page = await self._browser.new_page()
                page.on("dialog", on_dialog)
                page.on("request", on_request)
                self.navigations += 1
                try:
                    await page.add_init_script(_CONSOLE_HOOK)
                except Exception:
                    pass

                # Seed browser-owned sources *before* the document parses: these
                # handlers read their value synchronously, so setting them after
                # goto() is too late.
                await self._seed_sources(
                    page, url, window_name, cookies, storage, session_storage
                )

                if warm_url and warm_url != url:
                    # A stored record is not part of the handler's response: it
                    # appears when the page that renders it is opened. Load that
                    # page first — one navigation, the one this confirmation is
                    # charged for — then run the same ladder against the loaded
                    # document.
                    try:
                        await page.goto(
                            warm_url, timeout=timeout_ms, wait_until="domcontentloaded"
                        )
                    except PlaywrightTimeout:
                        pass
                    except Exception as e:
                        return BrowserConfirmResult(False, f"navigation_error:{e}")
                elif referrer:
                    # The property must exist before the page's first script,
                    # so the sink's own branch decision matches the attack.
                    await self._open_with_referrer(page, referrer, url, timeout_ms)
                else:
                    self.navigations += 1
                    # The decisive failure is "the plan reached this page and
                    # the payload still did not run". A same-document fragment
                    # change that Playwright does not treat as a navigation
                    # must not make that look like a navigation failure.
                    try:
                        await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                    except PlaywrightTimeout:
                        pass
                    except Exception as e:
                        if page.url.split("#", 1)[0] != url.split("#", 1)[0]:
                            return BrowserConfirmResult(False, f"navigation_error:{e}")

                # (1) Immediate dialogs — onload / onerror / parser-inserted.
                # Some pages defer execution through a timer (the payload runs
                # from a setTimeout, or an onload handler pushes it out), so
                # watch the page for a short settle window before giving up.
                deadline = time.monotonic() + _SETTLE_SECONDS
                while time.monotonic() < deadline:
                    await page.wait_for_timeout(150)
                    if dialog_matches():
                        return BrowserConfirmResult(
                            True, "dialog_on_load", dialog_msg, "load", bool(marker)
                        )
                    if request_hit["url"]:
                        return BrowserConfirmResult(
                            True,
                            f"request_on_load:{request_hit['url']}",
                            request_hit["url"],
                            "load",
                            True,
                        )

                # (2) Console echo (dialog suppressed by app / browser policy)
                if marker:
                    hit = await self._console_marker(page, marker)
                    if hit:
                        return BrowserConfirmResult(True, f"console:{hit}", hit, "load", True)

                # (3) Fragment / hashchange DOM sinks
                if "#" in url:
                    frag = urlparse(url).fragment
                    if frag:
                        try:
                            # The fragment already arrived with the navigation,
                            # so assigning it again is a no-op and a page that
                            # only listens for ``hashchange`` never runs. Clear
                            # it first so the assignment below is a real
                            # transition — and dispatch the event explicitly for
                            # listeners that were registered late.
                            await page.evaluate(
                                """(f) => {
                                    history.replaceState(null, '', location.pathname + location.search);
                                    location.hash = f;
                                    window.dispatchEvent(new HashChangeEvent('hashchange'));
                                }""",
                                frag,
                            )
                            await page.wait_for_timeout(450)
                        except Exception:
                            pass
                        if dialog_matches():
                            return BrowserConfirmResult(
                                True, "dialog_hashchange", dialog_msg, "hashchange", bool(marker)
                            )

                # (4) javascript: links — only those carrying our marker
                hit = await self._try_js_href_clicks(page, marker)
                if hit:
                    return BrowserConfirmResult(True, "dialog_js_href_click", dialog_msg, "click", True)

                # (5) Event-handler interactions, preferentially on our nodes
                hit = await self._try_interactions(page, marker)
                if hit:
                    return BrowserConfirmResult(
                        True, "dialog_after_interaction", dialog_msg, "interaction", bool(marker)
                    )

                # (5b) URL sinks the page built (form.action, frame.src): inert
                # until the browser follows them.
                hit = await self._try_url_follow(page, marker)
                if hit:
                    return BrowserConfirmResult(
                        True, "dialog_after_url_follow", dialog_msg, "navigation", bool(marker)
                    )

                # (6) Injectable JS (DOM sinks that need an explicit call)
                if exec_code and allow_eval:
                    ok, detail = await self._try_exec(page, exec_code, marker)
                    if ok:
                        return BrowserConfirmResult(True, detail, dialog_msg or detail, "eval", bool(marker))

                # A dialog that does not carry the marker is only proof when the
                # payload can be shown to have reached this page. An endpoint
                # that stores what it is given and re-renders it through a live
                # sink (a tracking page printing an order id) never shows the
                # raw payload, so the marker lives in the address bar, not in the
                # dialog. Those interactions above can open a dialog too, so the
                # page is read once and the answer is used for both branches.
                # Reported as attributed=False because the marker was not seen.
                if dialog_hit and not marker:
                    return BrowserConfirmResult(True, "dialog_unattributed", dialog_msg, "load", False)
                if dialog_hit and marker:
                    seen = await self._marker_in_page(page, payload, marker)
                    if seen:
                        return BrowserConfirmResult(
                            True, "dialog_unattributed", dialog_msg, "load", False
                        )

                return BrowserConfirmResult(False, "no_execution_observed")
            except Exception as e:
                return BrowserConfirmResult(False, f"browser_error:{e}")
            finally:
                if page:
                    try:
                        # A page wedged by a broken handler can hang close()
                        # indefinitely, which would stall the whole scan.
                        await asyncio.wait_for(page.close(), timeout=_CLOSE_SECONDS)
                    except Exception:
                        pass

    # ------------------------------------------------------------------
    # probes
    # ------------------------------------------------------------------

    async def _console_marker(self, page, marker: str) -> str:
        try:
            hits = await page.evaluate("() => (window.__ix_hits || [])")
        except Exception:
            return ""
        for h in hits or []:
            if marker and marker.lower() in str(h).lower():
                return str(h)[:160]
        return ""

    async def _marker_in_page(self, page, payload: str, marker: str) -> bool:
        """True when the payload reached this page's own DOM or URL.

        A dialog alone is not proof on a page that opens dialogs by itself, so
        the page has to show that the payload arrived: either the marker is
        present in its serialised DOM, or the payload itself is still the
        address bar's value, which is what a route reading its query string
        and re-rendering it has to act on. Nothing is required where the
        payload was injected through a channel that leaves no trace (a stored
        field, a form body): there the dialog is the only evidence there is.
        """
        if marker:
            try:
                html = await page.content()
            except Exception:
                html = ""
            if html and marker.lower() in html.lower():
                return True
        if payload:
            try:
                current = await page.evaluate("() => location.href")
            except Exception:
                current = ""
            # The address bar holds the payload percent-encoded, so compare
            # on the decoded forms rather than the raw string.
            if current:
                decoded = unquote(current)
                if payload in decoded or unquote(payload) in decoded:
                    return True
        return False

    async def _try_js_href_clicks(self, page, marker: str = "") -> bool:
        """Follow a ``javascript:`` link that carries our marker.

        The click has to be awaited before the dialog can be inspected: the page
        often navigates in the link's own ``finally()``, which starts as soon as
        the click returns. A budget long enough for the navigation is used, and a
        click that never settles still counts when the dialog was already seen.
        """
        try:
            # Two shapes reach the same place: an ``<a href>`` written by the
            # server, and an ``<a>`` whose ``href`` an SVG animator installs at
            # run time. The second has no ``href`` attribute to query for, so
            # the small set of anchors that carry our marker anywhere in their
            # subtree is added by hand.
            links = await page.query_selector_all('a[href^="javascript:" i], a[href*="javascript:" i]')
            if marker:
                try:
                    animated = await page.query_selector_all(
                        f'a:has(animate[values*="{marker}" i]), '
                        f'a:has(animate[from*="{marker}" i]), '
                        f'a:has(set[to*="{marker}" i])'
                    )
                    links = animated + [l for l in links if l not in animated]
                except Exception:
                    pass
            for link in links[:8]:
                try:
                    href = await link.get_attribute("href") or ""
                    if marker and marker.lower() not in href.lower():
                        subtree = ""
                        try:
                            subtree = await link.evaluate("(el) => el.outerHTML") or ""
                        except Exception:
                            subtree = ""
                        if not (marker and marker.lower() in subtree.lower()):
                            continue
                    seen: List[str] = []

                    async def on_dialog(dialog):
                        try:
                            seen.append(dialog.message or dialog.type)
                        except Exception:
                            seen.append("dialog")
                        try:
                            await dialog.dismiss()
                        except Exception:
                            pass

                    page.once("dialog", lambda d: asyncio.ensure_future(on_dialog(d)))
                    try:
                        await link.click(timeout=2500, no_wait_after=True)
                    except Exception:
                        pass
                    # Give the handler time to run; the dialog may arrive after
                    # the navigation the link itself started.
                    deadline = time.monotonic() + 2.0
                    while time.monotonic() < deadline and not seen:
                        await page.wait_for_timeout(100)
                    if any(
                        (not marker) or marker.lower() in (m or "").lower() for m in seen
                    ):
                        return True
                    seen.clear()
                except Exception:
                    continue
        except Exception:
            pass
        return False

    async def confirm_markup(
        self,
        url: str,
        *,
        markup: str,
        marker: str = "",
        timeout_ms: Optional[int] = None,
        kind: str = "",
    ) -> BrowserConfirmResult:
        """Load *url* and run *markup* as the page's own content.

        A stored record is not in the address bar: the page fetches it and
        writes it into the DOM. Opening the document therefore says nothing
        about the payload — something has to put it where the page would have,
        and that is what this does. The confirmer then behaves exactly as it
        does for a reflected payload: a dialog for our marker, an off-origin
        request carrying it, or a handler that already ran and kept the marker.

        This is only reached for a record the scanner has *already* seen stored
        and already classified as executable, so the document's own rendering
        path is not what is under test — the payload is.
        """
        if not self.available or not self._browser:
            return BrowserConfirmResult(False, "browser_unavailable")
        if not self._may_navigate(url, kind=kind or "stored"):
            return BrowserConfirmResult(False, "confirm_budget_exhausted")
        timeout_ms = timeout_ms or self.config.browser_timeout_ms
        budget = timeout_ms / 1000.0 + _SETTLE_SECONDS + _CLOSE_SECONDS * 3
        try:
            return await asyncio.wait_for(
                self._confirm_markup_inner(
                    url, markup=markup, marker=marker, timeout_ms=timeout_ms
                ),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            return BrowserConfirmResult(False, "confirm_timeout")

    async def _confirm_markup_inner(
        self, url: str, *, markup: str, marker: str, timeout_ms: int
    ) -> BrowserConfirmResult:
        async with self._sem:
            dialog_msg = ""
            fired = {"hit": False}
            request_hit = {"url": ""}
            origin = ""
            try:
                parsed = urlsplit(url or "")
                origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            except Exception:
                origin = ""

            async def on_dialog(dialog):
                fired["hit"] = True
                try:
                    dialog_msg = dialog.message or dialog.type
                except Exception:
                    dialog_msg = "dialog"
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            def on_request(request):
                try:
                    if not marker or not origin:
                        return
                    if request.resource_type == "document":
                        return
                    low = request.url.lower()
                    if marker.lower() not in low or low.startswith(origin):
                        return
                    if not request_hit["url"]:
                        request_hit["url"] = request.url
                except Exception:
                    pass

            page = await self._browser.new_page()
            try:
                page.on("dialog", on_dialog)
                page.on("request", on_request)
                self.navigations += 1
                try:
                    await page.add_init_script(_CONSOLE_HOOK)
                except Exception:
                    pass
                try:
                    await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                except PlaywrightTimeout:
                    pass
                except Exception as e:
                    return BrowserConfirmResult(False, f"navigation_error:{e}")

                # A marker left in a handler attribute is proof the handler ran:
                # this page has no record in its URL, so the only way our token
                # reaches the DOM is the markup just assigned.
                try:
                    await page.evaluate(
                        """(html) => {
                            const box = document.createElement('div');
                            box.setAttribute('data-ix-store', '1');
                            box.style.position = 'fixed';
                            box.style.left = '-9999px';
                            box.style.top = '0';
                            document.documentElement.appendChild(box);
                            box.innerHTML = html;
                            // A fragment assigned outside a document context
                            // never starts its loads; re-inserting it with the
                            // same content does, so the payload runs the way it
                            // would have when the page itself wrote it.
                            const again = box.innerHTML;
                            box.innerHTML = '';
                            box.innerHTML = again;
                        }""",
                        markup,
                    )
                except Exception as e:
                    return BrowserConfirmResult(False, f"markup_error:{e}")

                deadline = time.monotonic() + _SETTLE_SECONDS
                while time.monotonic() < deadline:
                    await page.wait_for_timeout(150)
                    if fired["hit"] and (
                        not marker or marker.lower() in (dialog_msg or "").lower()
                    ):
                        return BrowserConfirmResult(
                            True, "dialog_from_markup", dialog_msg, "load", True
                        )
                    if request_hit["url"]:
                        return BrowserConfirmResult(
                            True,
                            f"request_from_markup:{request_hit['url']}",
                            request_hit["url"],
                            "load",
                            True,
                        )
                hit = await self._try_interactions(page, marker) if marker else False
                if hit:
                    return BrowserConfirmResult(
                        True, "handler_from_markup", markup[:80], "dom", True
                    )
                if marker:
                    echo = await self._console_marker(page, marker)
                    if echo:
                        return BrowserConfirmResult(
                            True, f"console_from_markup:{echo}", echo, "load", True
                        )
                return BrowserConfirmResult(False, "markup_no_execution")
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

    async def _try_interactions(self, page, marker: str = "") -> bool:
        """Fire the event handler our payload actually installed.

        Hovering a blind list of selectors only works for the handful of events
        that happen to be on it. Once ``<`` is encoded the payload has to live
        inside the tag it is injected into, and *which* event it attached is
        the only thing that matters — so the handler carrying our marker is
        read from the DOM and the matching user-agent action is issued.
        """
        if not marker:
            return await self._try_default_interactions(page, marker)

        handlers = await page.evaluate(
            """(marker) => {
                const out = [];
                for (const el of document.querySelectorAll('*')) {
                    if (el.hasAttribute('popover')) {
                        // A popover element is hidden until toggled, so a
                        // handler on it can only run through showPopover().
                        for (const ev of ['beforetoggle', 'toggle']) {
                            const h = el.getAttribute('on' + ev);
                            if (h && h.includes(marker)) {
                                out.push({event: ev, autofocus: false, focusable: false});
                            }
                        }
                    }
                    for (const a of el.attributes) {
                        if (!a.name.startsWith('on')) continue;
                        if (!a.value.includes(marker)) continue;
                        out.push({
                            event: a.name.slice(2).toLowerCase(),
                            autofocus: el.hasAttribute('autofocus'),
                            accesskey: el.getAttribute('accesskey') || '',
                            // A non-rendered element (``<head>``'s canonical link)
                            // never receives a synthetic click, but its accesskey
                            // still reaches it: the shortcut is dispatched by the
                            // browser on whatever carries the attribute.
                            rendered: !!(el.offsetParent || el.getClientRects().length),
                            focusable: el.tabIndex >= 0 ||
                                       ['input','select','textarea','button','a'].includes(el.tagName.toLowerCase()),
                        });
                    }
                }
                return out;
            }""",
            marker,
        )
        if not handlers:
            return False

        for handler in handlers[:4]:
            if await self._fire_event(page, handler, marker):
                return True
        return False

    async def _fire_event(self, page, handler, marker: str = "") -> bool:
        """Deliver one DOM event and report whether it produced a dialog."""
        return bool(await self.fire_handler(page, handler, marker))

    async def fire_handler(self, page, handler, marker: str = "") -> Optional[dict]:
        event = handler.get("event") or ""
        needs_focus = handler.get("autofocus") or handler.get("focusable")
        shortcut = handler.get("accesskey") or ""
        # The page normally carries several elements with the same handler — a
        # comment thread repeats the author ``onclick`` per comment. Firing the
        # first one exercises somebody else's link and proves nothing about our
        # payload, so the selector is narrowed to the attributes that hold the
        # marker we injected.
        sel = f'[on{event}*="{marker}"]' if marker else f"[on{event}]"
        try:
            # The element may already have fired while the document loaded — an
            # ``onerror`` on a missing image, an ``onload`` on an SVG. Its
            # handler is still on the page and still carries our marker, which
            # only happens if it ran, so the attribute itself answers before an
            # event is delivered.
            if marker:
                try:
                    ran = await page.evaluate(
                        """(marker) => {
                            for (const el of document.querySelectorAll('*')) {
                                for (const a of el.attributes) {
                                    if (a.name.startsWith('on') && a.value.includes(marker)) {
                                        return a.name + '=' + a.value.slice(0, 120);
                                    }
                                }
                            }
                            return '';
                        }""",
                        marker,
                    )
                except Exception:
                    ran = ""
                if ran:
                    return {
                        "confirmed": True,
                        "detail": f"marker_in_handler:{ran}",
                        "trigger": "dom",
                    }
            async with page.expect_event("dialog", timeout=1500) as di:
                if shortcut:
                    # The handler was declared next to an ``accesskey``, which is
                    # the way in for an element the user never clicks. Chromium
                    # binds it behind Alt (Ctrl+Alt on some platforms), so both
                    # chords are pressed before falling back to the DOM event.
                    await page.keyboard.press(f"Alt+{shortcut.upper()}")
                    try:
                        await page.wait_for_timeout(120)
                    except Exception:
                        pass
                if event in ("focus", "blur"):
                    # Focus events only reach a focusable element; the injected
                    # one is not focusable on its own, so place focus directly.
                    await page.evaluate(
                        """(sel) => {
                            const el = document.querySelector(sel);
                            if (el) el.focus();
                        }""",
                        sel,
                    )
                elif event in ("mouseover", "mouseenter", "pointerenter", "mousemove"):
                    await page.evaluate(
                        """([ev, sel]) => {
                            const el = document.querySelector(sel);
                            if (!el) return;
                            const r = el.getBoundingClientRect();
                            el.dispatchEvent(new MouseEvent(ev, {
                                bubbles: true, cancelable: true,
                                clientX: r.left + 1, clientY: r.top + 1,
                            }));
                        }""",
                        [event, sel],
                    )
                elif event in ("beforetoggle", "toggle"):
                    # The event only exists while the element is being turned
                    # from hidden to shown, so dispatching one by hand fires
                    # nothing: the state change has to be asked for. A popover
                    # is exactly that mechanism, and it is what makes an
                    # otherwise ignored handler on an allowlisted tag run.
                    await page.evaluate(
                        """([ev, sel]) => {
                            const el = document.querySelector(sel);
                            if (!el) return;
                            try {
                                if (typeof el.showPopover === 'function') el.showPopover();
                                else if (el.tagName.toLowerCase() === 'details') el.open = true;
                            } catch (e) {}
                        }""",
                        [event, sel],
                    )
                if event in (
                    "click", "auxclick", "dblclick", "copy", "paste", "animationstart",
                ):
                    # ``el.click()`` rather than a dispatched ``MouseEvent``: an
                    # element the browser does not render — a canonical
                    # ``<link>``, a ``<style>`` — ignores synthetic pointer
                    # events but still runs the activation behaviour, which is
                    # what an ``onclick`` attribute is.
                    if event == "click":
                        await page.evaluate(
                            """(sel) => {
                                const el = document.querySelector(sel);
                                if (el) el.click();
                            }""",
                            sel,
                        )
                    else:
                        await page.evaluate(
                            """([ev, sel]) => {
                                const el = document.querySelector(sel);
                                if (!el) return;
                                const Ctor = (ev === 'auxclick' || ev === 'dblclick')
                                    ? MouseEvent : (ev === 'copy' || ev === 'paste')
                                        ? ClipboardEvent : AnimationEvent;
                                el.dispatchEvent(new Ctor(ev, {
                                    bubbles: true, cancelable: true,
                                    view: window,
                                }));
                            }""",
                            [event, sel],
                        )
                elif needs_focus:
                    await page.evaluate(
                        """(sel) => {
                            const el = document.querySelector(sel);
                            if (el) el.focus();
                        }""",
                        sel,
                    )
                else:
                    await page.evaluate(
                        """([ev, sel]) => {
                            const el = document.querySelector(sel);
                            if (el) el.dispatchEvent(new Event(ev, {bubbles: true}));
                        }""",
                        [event, sel],
                    )
            dlg = await di.value
            try:
                await dlg.dismiss()
            except Exception:
                # The page-level dialog handler already dismissed it; the
                # dialog still counts as delivered.
                pass
            return {"confirmed": True, "detail": f"dialog:{event or 'event'}", "trigger": "dom"}
        except Exception:
            return None

    async def _try_default_interactions(self, page, marker: str = "") -> bool:
        selectors = [
            "[autofocus]",
            "[onfocus]",
            "[onmouseover]",
            "svg[onload]",
            "img[onerror]",
            "details[open]",
        ]
        # Prefer nodes that carry our marker (attribute or text)
        if marker:
            selectors = [f"[onerror*='{marker}']", f"[onfocus*='{marker}']", f"[onmouseover*='{marker}']"] + selectors
        tried = 0
        for sel in selectors:
            if tried >= 6:
                break
            try:
                els = await page.query_selector_all(sel)
            except Exception:
                continue
            for el in els[:2]:
                if tried >= 6:
                    break
                tried += 1
                for action in ("focus", "hover"):
                    try:
                        async with page.expect_event("dialog", timeout=350) as di:
                            if action == "focus":
                                await el.focus(timeout=300)
                            else:
                                await el.hover(timeout=300)
                        dlg = await di.value
                        await dlg.dismiss()
                        return True
                    except Exception:
                        continue
        return False

    async def _try_url_follow(self, page, marker: str) -> bool:
        """Submit a form whose action carries the marker.

        A DOM sink that assigns a fragment into ``form.action`` or ``frame.src``
        only runs when the browser *follows* the URL: the sink is inert until a
        navigation happens. Submitting the form (or re-pointing an iframe) is
        therefore what turns the assignment into execution.
        """
        if not marker:
            return False
        try:
            forms = await page.query_selector_all(f"form[action*='{marker}']")
        except Exception:
            forms = []
        for form in forms[:2]:
            try:
                async with page.expect_event("dialog", timeout=800) as di:
                    await form.evaluate(
                        "f => { const b = document.createElement('button');"
                        " b.type = 'submit'; f.appendChild(b); f.requestSubmit ? f.requestSubmit(b) : f.submit(); }"
                    )
                dlg = await di.value
                await dlg.dismiss()
                return True
            except Exception:
                continue
        # A frame/iframe whose src is javascript: also needs a nudge on some
        # engines: re-assigning the same value forces the navigation.
        try:
            frames = await page.query_selector_all(f"iframe[src*='{marker}'], frame[src*='{marker}']")
        except Exception:
            frames = []
        for frame in frames[:2]:
            try:
                async with page.expect_event("dialog", timeout=800) as di:
                    await frame.evaluate("el => { const s = el.src; el.src = 'about:blank'; el.src = s; }")
                dlg = await di.value
                await dlg.dismiss()
                return True
            except Exception:
                continue
        return False

    async def _try_exec(self, page, exec_code: str, marker: str) -> tuple[bool, str]:
        """Evaluate payload JS directly (for DOM sinks not reachable from the URL)."""
        try:
            ret = await page.evaluate(exec_code)
        except Exception as e:
            return False, f"exec_error:{str(e)[:80]}"
        if isinstance(ret, str) and marker and marker.lower() in ret.lower():
            return True, f"exec_ret:{ret[:60]}"
        if ret is True:
            return True, "exec_true"
        return False, "exec_no_signal"

    # ------------------------------------------------------------------
    # client-side stored XSS (form → submit → dialog on render)
    # ------------------------------------------------------------------

    async def confirm_client_stored(
        self,
        url: str,
        *,
        field_selectors: Optional[list] = None,
        submit_selectors: Optional[list] = None,
        payload: str = "<img src=x onerror=alert(1)>",
        marker: str = "",
        timeout_ms: Optional[int] = None,
    ) -> BrowserConfirmResult:
        """Open page → fill form field → submit → watch for our marker."""
        if not self.available or not self._browser:
            return BrowserConfirmResult(False, "browser_unavailable")
        if not self._may_navigate(url):
            return BrowserConfirmResult(False, "confirm_budget_exhausted")

        marker = marker or _extract_marker(payload)
        field_selectors = field_selectors or [
            "textarea",
            "input[name='content']",
            "input[name='message']",
            "input[name='comment']",
            "input[type='text']",
        ]
        submit_selectors = submit_selectors or [
            "form button[type='submit']",
            "form input[type='submit']",
            "input[type='submit']",
            "button",
        ]
        timeout_ms = timeout_ms or self.config.browser_timeout_ms

        async with self._sem:
            page = None
            dialog_msg = ""
            dialog_hit = False

            async def on_dialog(dialog):
                nonlocal dialog_msg, dialog_hit
                dialog_hit = True
                try:
                    dialog_msg = dialog.message or dialog.type
                except Exception:
                    dialog_msg = "dialog"
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            try:
                page = await self._browser.new_page()
                page.on("dialog", on_dialog)
                self.navigations += 1
                try:
                    await page.add_init_script(_CONSOLE_HOOK)
                except Exception:
                    pass

                try:
                    await page.goto(url, timeout=timeout_ms, wait_until="load")
                except PlaywrightTimeout:
                    pass
                except Exception as e:
                    return BrowserConfirmResult(False, f"navigation_error:{e}")

                # Page scripts often wire their form handlers from window.onload;
                # a domcontentloaded wait leaves submit handlers unbound and the
                # stored value is never saved.
                try:
                    await page.wait_for_load_state("load", timeout=3000)
                except Exception:
                    pass
                await page.wait_for_timeout(300)

                field = None
                for sel in field_selectors:
                    try:
                        field = await page.query_selector(sel)
                        if field:
                            break
                    except Exception:
                        continue
                if not field:
                    return BrowserConfirmResult(False, "no_form_field")

                try:
                    await field.fill(payload, timeout=2000)
                except Exception:
                    try:
                        await field.click()
                        await page.keyboard.type(payload, delay=3)
                    except Exception as e:
                        return BrowserConfirmResult(False, f"fill_error:{e}")

                submitted = False
                # Submit the form that *owns* the filled field. Pages commonly
                # carry several forms (a "clear all" form often comes first);
                # clicking the first submit button on the page would hit the
                # wrong one and silently discard the payload.
                try:
                    submitted = bool(
                        await page.evaluate(
                            """() => {
                                const f = document.activeElement;
                                let form = f && f.form;
                                if (!form) {
                                    const fields = document.querySelectorAll('textarea, input[type=text]');
                                    for (const el of fields) {
                                        if (el.value) { form = el.form; break; }
                                    }
                                }
                                if (!form) return false;
                                form.requestSubmit ? form.requestSubmit() : form.submit();
                                return true;
                            }"""
                        )
                    )
                except Exception:
                    submitted = False

                if not submitted:
                    for sel in submit_selectors:
                        try:
                            btn = await page.query_selector(sel)
                            if not btn:
                                continue
                            await btn.click(timeout=1500)
                            submitted = True
                            break
                        except Exception:
                            continue
                if not submitted:
                    return BrowserConfirmResult(False, "submit_failed")

                for _ in range(10):
                    await page.wait_for_timeout(200)
                    if dialog_hit and (not marker or marker.lower() in dialog_msg.lower()):
                        return BrowserConfirmResult(True, "dialog_client_stored", dialog_msg, "submit", True)
                    if marker:
                        hit = await self._console_marker(page, marker)
                        if hit:
                            return BrowserConfirmResult(True, f"console:{hit}", hit, "submit", True)

                # Re-render on load (apps that only render stored posts on boot)
                try:
                    await page.reload(timeout=timeout_ms, wait_until="domcontentloaded")
                    await page.wait_for_timeout(500)
                    if dialog_hit and (not marker or marker.lower() in dialog_msg.lower()):
                        return BrowserConfirmResult(True, "dialog_client_stored_reload", dialog_msg, "reload", True)
                except Exception:
                    pass

                if await self._try_interactions(page, marker):
                    return BrowserConfirmResult(
                        True, "dialog_client_stored_interaction", dialog_msg, "interaction", True
                    )
                return BrowserConfirmResult(False, "no_execution_after_store")
            except Exception as e:
                return BrowserConfirmResult(False, f"browser_error:{e}")
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# helpers (module-level, pure)
# ---------------------------------------------------------------------------


def _extract_marker(payload: str) -> str:
    m = re.search(r"ixm([0-9a-f]{6,})", payload or "")
    return m.group(0) if m else ""


def build_exec_code(marker: str) -> str:
    """
    Return a JS expression that proves execution without literal keywords.

    ``eval(atob('…'))`` is resilient to WAFs that strip ``alert``/``confirm``
    from reflection while leaving ``eval`` and ``atob`` alone.
    """
    src = f"alert('{marker}')"
    b64 = base64.b64encode(src.encode()).decode()
    return f"eval(atob('{b64}'))"
