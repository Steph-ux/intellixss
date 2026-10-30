"""Target discovery: params, forms, fragments, JSON/API endpoints — path-scoped."""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, parse_qsl, urljoin, urlparse, urlunparse

from intellixss.config import Config
from intellixss.http.client import HttpClient
from intellixss.models import ScanTarget

try:
    from bs4 import BeautifulSoup

    HAS_BS4 = True
except ImportError:  # pragma: no cover - optional
    HAS_BS4 = False


# Only used when seed is the *site root* of xss-game (full-game scan).
XSSGAME_ALL_LEVELS = [
    ("/level1/frame", "GET", ["query"], None, "xssgame_l1"),
    ("/level2/frame", "CLIENT", ["content"], {"content": "test"}, "xssgame_l2_client"),
    ("/level3/frame", "GET", ["#fragment"], None, "xssgame_l3"),
    ("/level4/frame", "GET", ["timer"], None, "xssgame_l4"),
    ("/level5/frame/signup", "GET", ["next"], None, "xssgame_l5"),
    ("/level6/frame", "GET", ["gadget"], None, "xssgame_l6"),
]

# Subresource paths that never carry reflected input (noise + ban risk).
_SKIP_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|eot|mp4|webm|mp3|wav|zip|gz|pdf|exe|dmg|apk)(?:$|\?)",
    re.I,
)
_SKIP_PREFIX = re.compile(r"^(?:mailto:|tel:|javascript:|data:|#|blob:)", re.I)

# Common parameter names for same-origin JSON/API endpoints that take a body.
API_BODY_FIELDS = [
    "q", "query", "search", "message", "comment", "content", "body",
    "text", "name", "title", "description", "url", "redirect", "next",
]


def extract_params_from_url(url: str) -> List[str]:
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def _placeholder_for(inp) -> str:
    """A value the form will accept for a field we are not attacking.

    Sending the same literal for every field makes the submission fail its own
    validation: an ``<input type=email>`` named ``email`` rejects ``test`` with
    a 400 before the handler ever runs, so no injection on that form is ever
    evaluated. The placeholder follows the declared field type, which is what
    the browser does when it flags a malformed value.
    """
    kind = (inp.get("type") or "text").lower()
    name = (inp.get("name") or "").lower()
    if kind == "email" or (kind == "text" and "email" in name):
        return "scan@example.com"
    # An implicit type is a name the author chose. A field named ``email`` with
    # no ``type`` attribute is still an address to the validator behind the
    # handler, and it answers a 400 — with the error naming that field — before
    # the record is looked at. The name is the only evidence available, so it
    # is used, and the declared type wins when there is one.
    if kind == "url" or "website" in name or "url" in name or "link" in name:
        return "http://example.com"
    if kind == "tel" or "phone" in name:
        return "0600000000"
    if kind == "number" or "amount" in name or "qty" in name:
        return "1"
    if kind == "date":
        return "2024-01-01"
    if kind == "password":
        return "Passw0rd!"
    return "test"


def extract_forms(html: str, base_url: str) -> List[ScanTarget]:
    targets: List[ScanTarget] = []
    if not html:
        return targets
    if HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            action_url = urljoin(base_url, action)
            method = (form.get("method") or "GET").upper()
            params: List[str] = []
            data = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                params.append(name)
                # A field left empty is filled the way a visitor would fill it.
                # The record validator checks every attribute, not only the
                # ones marked ``required``, and a wrong placeholder is worse
                # than none: ``test`` in an address field makes the handler
                # reject the whole record with the *field's* error, so every
                # field on the form stays untested.
                data[name] = inp.get("value") or _placeholder_for(inp)
            if params:
                targets.append(
                    ScanTarget(
                        url=action_url,
                        method=method,
                        params=params,
                        data=data,
                        source="form",
                        source_url=base_url,
                    )
                )
        return targets

    for m in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        block = m.group(0)
        action_m = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', block, re.I)
        action_url = urljoin(base_url, action_m.group(1) if action_m else base_url)
        method = (method_m.group(1) if method_m else "GET").upper()
        names = re.findall(r'name=["\']([^"\']+)["\']', block, re.I)
        if names:
            # Every field gets its typed placeholder for the same reason as the
            # parser branch above: a whole-record validator rejects the POST on
            # the field it dislikes, whether or not that field is marked.
            data = {}
            for tag in re.finditer(r"<(input|textarea|select)\b[^>]*>", block, re.I):
                el = tag.group(0)
                m_name = re.search(r'name=["\']([^"\']+)["\']', el, re.I)
                if not m_name:
                    continue
                value_m = re.search(r'value=["\']([^"\']*)["\']', el, re.I)
                value = value_m.group(1) if value_m else ""
                if value:
                    data[m_name.group(1)] = value
                    continue
                kind_m = re.search(r'type=["\']([^"\']+)["\']', el, re.I)
                kind = kind_m.group(1).lower() if kind_m else "text"
                data[m_name.group(1)] = _placeholder_for(
                    {"type": kind, "name": m_name.group(1)}
                )
            targets.append(
                ScanTarget(
                    url=action_url,
                    method=method,
                    params=list(dict.fromkeys(names)),
                    data=data,
                    source="form",
                    source_url=base_url,
                )
            )
    return targets


def extract_links(html: str, base_url: str) -> List[str]:
    links: List[str] = []
    if HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            links.append(urljoin(base_url, a["href"]))
        for iframe in soup.find_all("iframe", src=True):
            links.append(urljoin(base_url, iframe["src"]))
        return links
    for m in re.finditer(r'(?:href|src)=["\']([^"\']+)["\']', html, re.I):
        links.append(urljoin(base_url, m.group(1)))
    return links


def _detect_fragment_usage(html: str) -> bool:
    if not html:
        return False
    patterns = [
        r"location\.hash",
        r"window\.location\.hash",
        r"self\.location\.hash",
        r"hashchange",
        r"document\.location\.hash",
    ]
    return any(re.search(p, html, re.I) for p in patterns)


def _detect_client_query_params(html: str) -> List[str]:
    """Return query parameter names the page's own script reads.

    A link is not the only way a parameter reaches a page: ``storeId`` can be
    read straight out of ``URLSearchParams`` and never appear in any href, so a
    link-only crawl finds nothing to inject into while the page is reading a
    parameter the user controls. Both accessors are covered — the
    ``URLSearchParams`` object and the older ``location.search`` parsing idiom.
    """
    if not html:
        return []
    names: List[str] = []

    def _keep(name: str) -> None:
        n = (name or "").strip()
        # A dynamically built key (``get(k)``) names nothing; only literals are
        # actionable without running the page.
        if not n or not re.fullmatch(r"[A-Za-z_][\w\-\.]{0,40}", n):
            return
        if n.lower() not in {x.lower() for x in names}:
            names.append(n)

    for m in re.finditer(
        r"""URLSearchParams\s*\([^)]*\)\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]""",
        html,
        re.I,
    ):
        _keep(m.group(1))
    for m in re.finditer(
        r"""\.\s*searchParams\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]""", html, re.I
    ):
        _keep(m.group(1))
    # ``?name=`` inside a hand-built query string (``location.search.split('?')``
    # style parsers) commonly names the key literally in a comparison.
    for m in re.finditer(
        r"""(?:search|query|qs)\s*[.=]\s*(?:split|match|indexOf|includes)\s*\([^)]*?['"]([A-Za-z_][\w\-\.]{0,40})['"]""",
        html,
        re.I,
    ):
        _keep(m.group(1))
    # The page often stores the parser first:
    # ``var p = new URLSearchParams(location.search); … p.get('storeId')``.
    # Once a URLSearchParams object exists, any ``.get('literal')`` on a local
    # is a query key, since the object is only built from the query string.
    if re.search(r"URLSearchParams\s*\(", html, re.I):
        for m in re.finditer(
            r"""\.\s*get\s*\(\s*['"]([A-Za-z_][\w\-\.]{0,40})['"]\s*\)""", html, re.I
        ):
            _keep(m.group(1))
    return names[:12]


def _path_prefix(seed_url: str) -> str:
    """Return path used for scope (e.g. /level1). Empty or / = site root."""
    path = urlparse(seed_url).path or "/"
    path = path.rstrip("/") or "/"
    return path


def _query_value_count(url: str) -> int:
    """Number of query parameters carrying a non-empty value.

    Used to pick the richer of two equivalent targets: ``?q=hi&lang=fr`` beats
    ``?q=`` because sibling values can change what the page renders.
    """
    return sum(1 for _k, v in parse_qsl(urlparse(url).query, keep_blank_values=True) if v)


def _is_site_root(seed_url: str) -> bool:
    path = _path_prefix(seed_url)
    return path in ("/", "")


def _same_scope(url: str, seed_url: str) -> bool:
    """
    Keep discovery inside the user's requested path prefix.

    - seed https://host/level1  → only URLs under /level1...
    - seed https://host/        → whole host (subject to max_urls)
    """
    seed_host = urlparse(seed_url).netloc
    u = urlparse(url)
    if u.netloc != seed_host:
        return False
    if _is_site_root(seed_url):
        return True
    seed_path = _path_prefix(seed_url)
    upath = (u.path or "/").rstrip("/") or "/"
    return upath == seed_path or upath.startswith(seed_path + "/")


def _xssgame_level_from_path(path: str) -> Optional[str]:
    m = re.search(r"/level(\d+)", path, re.I)
    return m.group(1) if m else None


def discover_js_endpoints(html: str, base_url: str) -> List[str]:
    """Same-origin endpoint paths referenced from inline JS (fetch/axios/$http)."""
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    seen: Set[str] = set()
    out: List[str] = []
    patterns = [
        r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""axios\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""\$\.(?:ajax|get|post)\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""['"`](/api/[^'"`\s]+)['"`]""",
        r"""['"`](/(?:rest|v\d|graphql)[^'"`\s]*)['"`]""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, html or "", re.I):
            path = m.group(1)
            if _SKIP_PREFIX.match(path):
                continue
            full = urljoin(base_url, path)
            if urlparse(full).netloc != urlparse(origin).netloc:
                continue
            clean = urlunparse(urlparse(full)._replace(fragment=""))
            if clean not in seen:
                seen.add(clean)
                out.append(clean)
    return out


async def _offer_api_body(client: HttpClient, url: str) -> bool:
    """True when the endpoint accepts a JSON POST with a common body field."""
    payload = {f: "test" for f in API_BODY_FIELDS[:3]}
    st, body, hdrs, _ = await client.request("POST", url, json_body=payload)
    if st in (0, 404, 405, 415, 501):
        return False
    ctype = (hdrs or {}).get("Content-Type", "").lower()
    return "json" in ctype or "html" in ctype or (st < 400 and _looks_json(body))


def _looks_json(body: str) -> bool:
    b = (body or "").strip()
    if not b or b[0] not in "{[":
        return False
    try:
        json.loads(b)
        return True
    except Exception:
        return False


# Conventional names for a page's own search/filter input. Ordered by how often
# a real app uses them; the pass stops at the first few that are echoed.
_GUESS_PARAMS: tuple = ("search", "q", "query", "s", "keyword", "term")
_GUESS_CANARY = "ixgcanary7"

# Fields that carry the request's own machinery rather than user content. A
# token is not an injectable value: sending a different one makes every request
# on the form fail, so neither the form nor a GET needs to be attributed to it.
_STRUCTURAL_FIELD_NAMES = {
    "csrf",
    "csrf_token",
    "_csrf",
    "_token",
    "authenticity_token",
    "postid",
    "productid",
    "itemid",
    "id",
}


async def _guess_reflected_params(
    client: HttpClient,
    page_url: str,
    add,
    seed_url: str,
    pages: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Names from ``_GUESS_PARAMS`` that *page_url* echoes back.

    A name is only kept when sending it changes the response and the canary
    comes back in it. Asking for a name a handler ignores returns the untouched
    page, so this both avoids scanning dead parameters and keeps the budget at
    one request per candidate name.

    *pages* maps a crawled URL to the body already fetched for it. Reusing it
    keeps the pass at one request per candidate without a second baseline, and
    a page that was never crawled is fetched once here.
    """
    from urllib.parse import urlencode, urlsplit, urlunsplit

    base = urlsplit(page_url.split("#")[0])
    if base.query:
        # The seed already carries parameters; appending a guessed name to them
        # is a different request than the one a tester makes, and the handler
        # may reject the combination.
        return []
    reference = (pages or {}).get(page_url) or (pages or {}).get(
        urlunsplit((base.scheme, base.netloc, base.path, "", ""))
    )
    if not reference:
        try:
            _, reference, _, _ = await client.request("GET", page_url)
        except Exception:
            return []
    hits: List[str] = []
    for name in _GUESS_PARAMS:
        if len(hits) >= 2:
            break
        url = urlunsplit(
            (base.scheme, base.netloc, base.path, urlencode({name: _GUESS_CANARY}), "")
        )
        try:
            st, body, _, _ = await client.request("GET", url)
        except Exception:
            continue
        if st == 0 or not body or _GUESS_CANARY not in body:
            continue
        if body == reference:
            continue
        hits.append(name)
    return hits


guess_reflected_params = _guess_reflected_params


async def discover_targets(
    client: HttpClient,
    seed_url: str,
    config: Config,
) -> List[ScanTarget]:
    """
    Build injectable targets from the seed URL.

    Scope rules:
    - User URL path is respected (level1 only scans under /level1).
    - Full xss-game level fan-out only when seed is the site root.
    """
    # Keyed by what the scanner actually drives — method, path and parameter
    # set — not by the literal query string. ``?q=hi`` and ``?q=`` reach the
    # same handler and every request rewrites the query anyway, so keeping both
    # scans the parameter twice and reports the same XSS under two markers.
    seen: Dict[str, ScanTarget] = {}
    targets: List[ScanTarget] = []
    host = urlparse(seed_url).netloc
    origin = f"{urlparse(seed_url).scheme}://{host}"
    is_xss_game = "xss-game" in host or "xssgame" in host
    seed_path = _path_prefix(seed_url)
    level = _xssgame_level_from_path(seed_path)

    def add(t: ScanTarget) -> None:
        if not _same_scope(t.url, seed_url):
            return
        if _SKIP_EXT.search(t.url):
            return
        key = f"{t.method}:{urlparse(t.url).path.split('#')[0]}:{'|'.join(sorted(t.params))}"
        # A client-side parameter and a linked one can live on the same path
        # with disjoint names; each has to be scanned on its own so the flow it
        # provokes is attributed to the parameter that actually caused it.
        if t.source == "client_query":
            key += f":{t.source}"
        prior = seen.get(key)
        if prior is not None:
            # Same parameter set: keep the URL that carries real values, since
            # a sibling query parameter can change what the page renders.
            if _query_value_count(t.url) > _query_value_count(prior.url):
                prior.url = t.url
                prior.data = t.data or prior.data
                prior.source = t.source
            return
        seen[key] = t
        if t.params:
            targets.append(t)

    # --- Seed params ---
    seed_params = extract_params_from_url(seed_url)
    if seed_params:
        add(ScanTarget(url=seed_url, method="GET", params=seed_params, source="seed"))

    status, body, _, final = await client.request("GET", seed_url)

    # --- Page forms / fragment / same-scope links / JS endpoints ---
    if status and body:
        page_url = final or seed_url
        for form_t in extract_forms(body, page_url):
            add(form_t)
        # A field's value is not only *written* through the form: the page that
        # renders the record often reads the same name from its own query
        # string and prints it back unencoded (``?email=`` in the account page
        # that the email form itself sits on). That path costs one request per
        # field and is invisible to a form-only view of the page, so each field
        # is also offered as a GET on the page the form was served from.
        _seen_fields: set = set()
        for form_t in extract_forms(body, page_url):
            for name in form_t.params:
                if name in _seen_fields or name.lower() in _STRUCTURAL_FIELD_NAMES:
                    continue
                _seen_fields.add(name)
                add(
                    ScanTarget(
                        url=page_url.split("#")[0],
                        method="GET",
                        params=[name],
                        source="form_field_get",
                    )
                )

        if _detect_fragment_usage(body):
            add(
                ScanTarget(
                    url=page_url.split("#")[0],
                    method="GET",
                    params=["#fragment"],
                    source="fragment",
                )
            )

        # Parameters the page reads in script but never links to. They are
        # driven through the same page, so the rendered document still goes
        # through the normal DOM-flow analysis once they are injected. Each is
        # added as its own target: the DOM flow that consumes one of them has
        # to be attributed to that name, not merged into the visible ones.
        for cname in _detect_client_query_params(body):
            add(
                ScanTarget(
                    url=page_url.split("#")[0],
                    method="GET",
                    params=[cname],
                    source="client_query",
                )
            )

        for link in extract_links(body, page_url):
            if not _same_scope(link, seed_url):
                continue
            if _SKIP_PREFIX.match(link) or _SKIP_EXT.search(link):
                continue
            if len(targets) >= config.max_urls:
                break
            params = extract_params_from_url(link)
            if params:
                add(ScanTarget(url=link, method="GET", params=params, source="link"))

        # JSON API endpoints discovered in inline JS
        for ep in discover_js_endpoints(body, page_url)[:6]:
            if not _same_scope(ep, seed_url):
                continue
            if await _offer_api_body(client, ep):
                add(
                    ScanTarget(
                        url=ep,
                        method="POST",
                        params=list(API_BODY_FIELDS[:6]),
                        data={f: "test" for f in API_BODY_FIELDS[:6]},
                        source="api_json",
                    )
                )

        # A parameter the page consumes but never exposes: no link, no form, no
        # script reference. Trying the conventional names is what a tester does
        # after reading a hint, and it is the only route to that sink. The pass
        # is bounded and only reports a name that the page actually echoes.
        if config.guess_params:
            names = await _guess_reflected_params(
                client, page_url, add, seed_url, {page_url: body, seed_url: body}
            )
            for name in names:
                add(
                    ScanTarget(
                        url=page_url.split("#")[0],
                        method="GET",
                        params=[name],
                        source="guess",
                    )
                )

    # --- xss-game: scoped level hints (only the requested level, or all if root) ---
    if is_xss_game:
        if _is_site_root(seed_url):
            for path, method, params, data, src in XSSGAME_ALL_LEVELS:
                add(
                    ScanTarget(
                        url=f"{origin}{path}",
                        method=method,
                        params=list(params),
                        data=dict(data or {}),
                        source=src,
                    )
                )
        elif level:
            await _add_xssgame_level(client, add, origin, level, seed_url)

    # --- Fallback: default params on seed if still empty ---
    if not targets:
        if is_xss_game and level == "1":
            frame = f"{origin}/level1/frame"
            add(ScanTarget(url=frame, method="GET", params=["query"], source="xssgame_l1"))
        else:
            add(
                ScanTarget(
                    url=seed_url,
                    method="GET",
                    params=list(config.default_params[:6]),
                    source="default_params",
                )
            )

    return targets[: config.max_urls]


async def _add_xssgame_level(client, add, origin: str, level: str, seed_url: str) -> None:
    """Register injectable points for a single xss-game level only."""
    if level == "1":
        frame = f"{origin}/level1/frame"
        st, html_b, _, fin = await client.request("GET", frame)
        page = fin or frame
        add(ScanTarget(url=page, method="GET", params=["query"], source="xssgame_l1"))
        if st and html_b:
            for form_t in extract_forms(html_b, page):
                add(form_t)
    elif level == "2":
        frame = f"{origin}/level2/frame"
        add(
            ScanTarget(
                url=frame,
                method="CLIENT",
                params=["content"],
                data={"content": "test"},
                source="xssgame_l2_client_stored",
            )
        )
        st, html_b, _, fin = await client.request("GET", frame)
        page = fin or frame
        if st and html_b:
            for form_t in extract_forms(html_b, page):
                form_t.method = "CLIENT"
                form_t.source = "xssgame_l2_form"
                add(form_t)
    elif level == "3":
        frame = f"{origin}/level3/frame"
        add(ScanTarget(url=frame, method="GET", params=["#fragment"], source="xssgame_l3"))
    elif level == "4":
        frame = f"{origin}/level4/frame"
        add(ScanTarget(url=frame, method="GET", params=["timer"], source="xssgame_l4"))
    elif level == "5":
        signup = f"{origin}/level5/frame/signup"
        add(ScanTarget(url=signup, method="GET", params=["next"], source="xssgame_l5"))
        frame = f"{origin}/level5/frame"
        if _same_scope(frame, seed_url):
            st, html_b, _, _ = await client.request("GET", frame)
            if st and html_b:
                for form_t in extract_forms(html_b, frame):
                    add(form_t)
    elif level == "6":
        frame = f"{origin}/level6/frame"
        # The gadget name is read from location.hash, not from a query
        # parameter: probe it through the fragment scanner.
        add(ScanTarget(url=frame, method="GET", params=["#fragment"], source="xssgame_l6"))
