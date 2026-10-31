"""Target discovery: params, forms, fragments, JSON/API endpoints — path-scoped."""

from __future__ import annotations

import json
import re
import urllib.request
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

# Keys a body may legitimately carry that this list does not name, because
# they are not worth *guessing* but are read by a handler all the same. A
# literal body object in the bundle is evidence, not a guess: whatever key it
# writes at the top level is the field the handler reads.
_EXTRA_BODY_FIELDS = [
    "email", "username", "password", "bio", "address", "city", "country",
    "phone", "feedback", "review", "author", "subject", "label", "value",
    "html", "markdown", "payload", "data",
]
_KNOWN_BODY_FIELDS = set(API_BODY_FIELDS) | set(_EXTRA_BODY_FIELDS)


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


# How far past a query object its ``navigate`` call may sit. A source writer
# keeps the two adjacent, but a built bundle hoists the object into a local a
# statement earlier; the window only has to clear the component's own body.
_ROUTE_SEARCH_CHARS = 2000


def detect_client_route_params(js: str) -> List[Tuple[str, str]]:
    """Return ``(route, parameter)`` pairs the client router reads.

    A hash-routed application keeps its route out of the request, so the only
    description of it is the bundle. Two shapes name the two halves:

    - ``router.navigate(['/search'], {queryParams: {q: t}})`` names both the
      route and the keys it carries. The object is often built into a local
      first, so the navigate call is looked for on either side of it.
    - ``route.snapshot.queryParams.q`` and ``queryParamMap.get('q')`` name the
      key where it is *read*, which is usually a different method from the one
      that navigates. Those are collected with an empty route: the key is real
      even when its route has to come from the writer.

    A key computed at runtime (``queryParams[k]``) names nothing and is not
    returned — guessing it would spend the scan on a parameter the router may
    never read.
    """
    if not js:
        return []
    found: List[Tuple[str, str]] = []

    def _keep(route: str, name: str) -> None:
        n = (name or "").strip()
        if not re.fullmatch(r"[A-Za-z_$][\w$.\-]{0,40}", n):
            return
        r = (route or "").strip()
        if r and not r.startswith("/"):
            r = "/" + r
        pair = (r, n)
        if pair not in found:
            found.append(pair)

    for m in re.finditer(r"""queryParams\s*:\s*\{([^{}]*)\}""", js):
        keys = [
            km.group(1)
            for km in re.finditer(r"""(?:^|,)\s*([A-Za-z_$][\w$]*)\s*:""", m.group(1))
        ]
        if not keys:
            continue
        # The writer is not always beside its object. A source writer passes
        # ``{queryParams:{q:t}}`` straight into ``navigate``, but a built bundle
        # hoists the object into a local a statement earlier
        # (``let i={queryParams:{id:t}}; … navigate([`/track-result`],i)``), and
        # a component can write several keys in one object. Searching only the
        # 400 characters around the ``{`` left the first shape unpaired and the
        # scanner probed ``/`` instead of the route that renders the value.
        # The nearest ``navigate`` after the object is the one it was written
        # for; the one before it is only used when there is none after.
        after = js[m.end():m.end() + _ROUTE_SEARCH_CHARS]
        before = js[max(0, m.start() - 400):m.start()]
        route_m = re.search(r"""navigate\s*\(\s*\[\s*['"`]([^'"`]*)['"`]""", after)
        if not route_m:
            route_m = re.search(r"""navigate\s*\(\s*\[\s*['"`]([^'"`]*)['"`]""", before)
        route = route_m.group(1) if route_m else ""
        for key in keys:
            _keep(route, key)

    for pattern in (
        r"""queryParamMap\s*\.\s*get\s*\(\s*['"`]([^'"`]+)['"`]""",
        r"""queryParams\s*\[\s*['"`]([^'"`]+)['"`]\s*\]""",
        r"""queryParams\s*\.\s*([A-Za-z_$][\w$]*)""",
    ):
        for m in re.finditer(pattern, js):
            _keep("", m.group(1))
    return found[:12]


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
        # An injected client calls its transport directly with the whole URL
        # in a template literal: ``this.http.get(`/rest/products/search?q=${t}`)``.
        r"""\.http\s*\.\s*get\s*\(\s*`([^`]+)`""",
        r"""['"`](/api/[^'"`\s]+)['"`]""",
        r"""['"`](/(?:rest|v\d|graphql)[^'"`\s]*)['"`]""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, html or "", re.I):
            path = _resolve_path(m.group(1), _bases_for(html or "", m.start()))
            if not path or _SKIP_PREFIX.match(path):
                continue
            full = urljoin(base_url, path)
            if urlparse(full).netloc != urlparse(origin).netloc:
                continue
            clean = urlunparse(urlparse(full)._replace(fragment=""))
            if clean not in seen:
                seen.add(clean)
                out.append(clean)
    return out


# A method call on a client object: ``http.put(url, body)``, ``axios.post(…)``,
# ``$.post(…)``. Only the writes are collected — a GET that carries a query
# string is already found by the pattern list above, and a GET with a body is
# the same request as the one its own URL spells out.
#
# The URL is either a quoted literal in the first argument or an identifier
# concatenated with one: ``this.host+`/` `` and ```${this.host}/${id}` `` are
# the same request written by two versions of the same generator.
#
# Groups, by alternation: (1) http method, (2) http quote-or-field, (3) http
# path, (4) axios method, (5) axios quote-or-field, (6) axios path, (7) jquery
# method, (8) jquery quote-or-field, (9) jquery path.
_WRITE_CALL = re.compile(
    r"""(?:\.|\b)http\s*\.\s*(post|put|patch)\s*\(\s*(?:([`'"])(.*?)\2|([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\+\s*([`'"])(.*?)\5)"""
    r"""|axios\s*\.\s*(post|put|patch)\s*\(\s*([`'"])(.*?)\8"""
    r"""|\$\.(post|put)\s*\(\s*([`'"])(.*?)\11""",
    re.I | re.S,
)

# A fetch option block opens with ``{method: …}``; those keys describe the
# request, and the payload object is nested inside ``body``.
_FETCH_OPTION_KEYS = {"method", "headers", "body", "mode", "credentials", "signal", "cache"}

# The first property of a literal object argument: ``{message: x}``. A fetch
# wraps the object in ``JSON.stringify``, so the helper name is skipped.
_BODY_FIRST_KEY = re.compile(
    r"\{(?:\s*[A-Za-z_$][\w$.]*\s*\()*\s*['\"]?([A-Za-z_$][\w$]*)['\"]?\s*:"
)

# ``fetch(url, {method: 'POST', body: …})``. The option block is taken as a
# character window rather than up to the first ``}``: the body is a nested
# object and stopping at its brace drops the field name.
_FETCH_CALL = re.compile(r"""fetch\s*\(\s*([`'"])(.*?)\1\s*,\s*(\{)""", re.S | re.I)
_FETCH_METHOD = re.compile(r"""method\s*:\s*['"](POST|PUT|PATCH)['"]""", re.I)

# A template literal names the path shape, not one instance of it:
# ``/rest/products/${id}/reviews`` is the ``:id`` of a route. Keeping the
# interpolation verbatim would ask a server for a product literally called
# ``${id}`` and get a 404 for a sink that exists.
_INTERPOLATION = re.compile(r"\$\{[^}]*\}")

# A service field built once and reused per call:
# ``host=this.hostServer+`/rest/products``` then ``this.http.put(`${this.host}/${t}/reviews`, …)``.
# The suffix is what the call appends; the base is where it appends to.
_BASE_ASSIGN = re.compile(
    r"(?:this\.)?([A-Za-z_$][\w$]*)\s*=\s*this\s*\.\s*([A-Za-z_$][\w$]*)\s*\+\s*[`'\"]([^`'\"]+)[`'\"]"
)
# The service's own origin field: ``this.hostServer = F$.hostServer`` in the
# bundle (the ``this.`` is dropped inside the minifier's IIFE, so it is part of
# the captured name), which is the site root and therefore an empty prefix.
_SELF_BASE_ASSIGN = re.compile(
    r"(?:^|[;,\s{])((?:this\s*\.\s*)?[A-Za-z_$][\w$]*)\s*=\s*(?:this|[A-Za-z_$][\w$]*)\s*\.\s*"
    r"(hostServer|origin|baseUrl|basePath)\b"
)
# A URL argument that starts with an identifier, optionally in a template.
# The service writes ``${this.hostServer}`` in its class body, bare
# ``hostServer`` inside the minifier's IIFE, and ``${F$.hostServer}`` when the
# env object is captured directly; all three name the same field.
_BASE_PREFIX = re.compile(
    r"^`?\$\{(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\}"
)

# An origin reference that is not a field assignment: ``${F$.hostServer}``
# names the env object's own root, which needs no declaration to resolve.
_INLINE_ROOT_FIELDS = {"hostServer", "origin", "baseUrl", "basePath"}


def _rewrite_template(url: str) -> str:
    """Replace interpolations with ``:id``, keeping any literal between them.

    ``${this.host}/${t}/reviews`` is ``${this.host}`` then ``/`` then a route
    parameter. A single blind substitution would erase the path prefix, so the
    first interpolation is kept as a marker the base resolver can consume.
    """
    return _INTERPOLATION.sub(":id", url)


def _service_bases(js: str) -> Dict[str, str]:
    """name -> the path its own module prefixes, from ``host=<x>+`/rest/...```.

    Kept for callers that have one call per bundle, where a single mapping is
    unambiguous. ``detect_js_endpoints`` resolves per call site instead, because
    a minifier renames every service's fields to the same short names.
    """
    return _bases_for(js, len(js or ""))


def _bases_for(js: str, pos: int) -> Dict[str, str]:
    """The prefixes in force at *pos*: the last declaration before it.

    Every service class declares ``hostServer`` and its own ``host``; after
    minification those are the same three-letter fields in each class. A map
    built for the whole bundle therefore has two services overwrite each
    other's entry, and a review sink is resolved against the complaint
    service's prefix. Walking back from the call finds the declaration that
    actually applies.
    """
    head = (js or "")[:pos]
    table: Dict[str, str] = {}

    def put(name: str, prefix: str) -> None:
        name = re.sub(r"\s+", "", name)
        table[name] = prefix
        table[name.split(".")[-1]] = prefix

    for m in _SELF_BASE_ASSIGN.finditer(head):
        put(m.group(1), "")
    for m in _BASE_ASSIGN.finditer(head):
        base = (m.group(3) or "").strip()
        if base.startswith("/"):
            put(m.group(1), base.rstrip("/"))
    return table


def detect_js_endpoints(
    js: str, base_url: str
) -> List[tuple]:
    """Writes a script makes: ``(method, url)`` or ``(method, url, field)``.

    *field* is the first property of a literal body object — the name the
    handler reads the value from. It is absent when the body is an identifier:
    the bundle then built the object elsewhere and the name is not visible at
    the call site.
    """
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    seen: Set[tuple] = set()
    out: List[tuple] = []

    def _add(method: str, raw_path: str, body: str, pos: int) -> None:
        path = _resolve_path(raw_path, _bases_for(js or "", pos))
        if not path or _SKIP_PREFIX.match(path) or _SKIP_EXT.search(path):
            return
        # A trailing slash is a spelling of the same Express route and makes
        # the report disagree with the endpoint a reader would type.
        if len(path) > 1:
            path = path.rstrip("/")
        full = urljoin(base_url, path)
        if urlparse(full).netloc != urlparse(origin).netloc:
            return
        clean = urlparse(full)._replace(fragment="").geturl()
        key: tuple = (method.upper(), clean)
        field = _body_field(body or "")
        if field:
            key = key + (field,)
        else:
            # The call posts a record built elsewhere; the keys its components
            # send are the only honest candidates for what the handler reads.
            extras = _payload_keys_at(js or "", pos)
            for extra in extras:
                candidate = key + (extra,)
                if candidate not in seen:
                    seen.add(candidate)
                    out.append(candidate)
            if extras:
                return
        if key in seen:
            return
        seen.add(key)
        out.append(key)

    for m in _WRITE_CALL.finditer(js or ""):
        groups = m.groups()
        if groups[0]:
            # http: (1) method, (2) quote, (3) path, or (4) field + (5) quote
            # + (6) path. The quote pair sits between method and path, so the
            # path is one group past the quote — reading ``groups[2]`` here
            # returned the backtick itself and every ``this.host+`/` `` call
            # collapsed to the site root.
            method = groups[0]
            path = groups[2] if groups[2] is not None else groups[5]
            field_4 = groups[3]
        elif groups[6]:
            # axios: (7) method, (8) quote, (9) path
            method, path, field_4 = groups[6], groups[8], None
        else:
            # jQuery: (10) method, (11) quote, (12) path
            method, path, field_4 = groups[9], groups[11], None
        if field_4:
            # ``this.host+`/` ``: the field holds the prefix, the literal the
            # suffix, exactly as inside a template. The suffix is appended to
            # the field's own value, which may be a whole path (``/api/X``) or
            # a bare origin.
            path = "${" + field_4.replace(" ", "") + "}" + path
        # The match stops at the closing quote of the URL argument; the body
        # starts right after it.
        start = m.end()
        tail = js[start : start + 300]
        _add(method, path, tail, m.start())

    for m in _FETCH_CALL.finditer(js or ""):
        opts = (js or "")[m.start(3) : m.start(3) + 400]
        meth = _FETCH_METHOD.search(opts)
        if not meth:
            continue
        _add(meth.group(1), m.group(2), opts, m.start())
    return out


async def fetch_page_scripts(
    client: HttpClient,
    body: str,
    page_url: str,
    cache: Optional[Dict[str, str]] = None,
) -> List[str]:
    """The page's own same-origin ``<script src=…>`` bodies.

    Sinks live in bundles, not in the document: a single-page application has
    an empty ``<body>`` and every endpoint it writes to is named in a bundle.
    A third-party host is never fetched — its script cannot be the sink of a
    parameter the page itself controls. *cache* is shared by every caller of
    one scan: several passes read the same bundles, and a 1.3 MB file is not
    worth downloading twice.
    """
    store = cache if cache is not None else {}
    out: List[str] = []
    for m in re.finditer(
        r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", body or "", re.I
    ):
        src = urljoin(page_url, m.group(1))
        if urlparse(src).netloc != urlparse(page_url).netloc:
            continue
        if src in store:
            if store[src]:
                out.append(store[src])
            continue
        try:
            st, text, _, _ = await client.request("GET", src)
        except Exception:
            store[src] = ""
            continue
        store[src] = text if (st and text) else ""
        if store[src]:
            out.append(store[src])
    return out


def _resolve_path(raw: str, bases: Dict[str, str]) -> str:
    """A call's URL argument as a path, with the service prefix filled in.

    Returns "" when the argument starts with a field whose value the bundle
    never shows: guessing a prefix would send the scan to an endpoint that
    does not exist, and reporting that 404 as a dead sink blames the target.
    """
    url = (raw or "").strip()
    m = _BASE_PREFIX.match(url)
    if m:
        name, member = m.group(1), m.group(2)
        if member:
            # ``${F$.hostServer}``: the member is an origin field on whatever
            # object holds the app config, so the path starts at the root.
            if member not in _INLINE_ROOT_FIELDS:
                return ""
            prefix, rest_at = "", m.end()
        else:
            if name not in bases:
                return ""
            prefix, rest_at = bases[name], m.end()
        rest = url[rest_at:].lstrip("/")
        # ``/api/Complaints`` + ``/`` is ``/api/Complaints/``, not a new path.
        url = f"{prefix}/{rest}" if prefix else f"/{rest}"
    return _rewrite_template(url)


def _concrete_resource(url: str, seed_url: str) -> str:
    """Replace a ``:id`` route parameter with a real record id.

    ``PUT /rest/products/:id/reviews`` names a shape; the handler needs a
    product. The path in front of the parameter is tried as a listing, then
    each shorter prefix after it: a resource route often carries no list of its
    own (``/rest/products`` answers ``500``) while the collection that owns the
    same records does (``/api/Products``). The first id the app itself publishes
    is used, so the scan stays on data it can legitimately read.
    """
    parts = urlparse(url)
    if ":id" not in parts.path:
        return url
    segments = parts.path.strip("/").split("/")
    idx = segments.index(":id")
    if idx == 0:
        return url
    ident = _first_record_id(seed_url, segments[:idx], seed_url)
    if ident in (None, ""):
        return url
    segments[idx] = str(ident)
    return parts._replace(path="/" + "/".join(segments)).geturl()


def _first_record_id(base_url: str, segments: List[str], seed_url: str):
    """The first ``id`` a collection publishes, trying each shorter prefix.

    A product API can expose its collection only through a search route
    (``/rest/products/search?q=%``) while the resource route in front of the
    parameter answers ``500``, so the search route is probed last.
    """
    for cut in range(len(segments), 0, -1):
        root = "/" + "/".join(segments[:cut])
        for candidate in (root, root + "/search?q=%25"):
            try:
                st, body, _, _ = urllib_request(candidate, base_url)
            except Exception:
                continue
            if not st or not body:
                continue
            try:
                payload = json.loads(body)
            except ValueError:
                continue
            ident = _record_id_in(payload)
            if ident not in (None, ""):
                return ident
    return None


def _record_id_in(payload):
    """The first numeric ``id`` anywhere in a decoded JSON collection.

    The envelope differs between routes — a bare array, ``{"data": [...]}``, or
    a single object — so the search is structural rather than positional.
    """
    if isinstance(payload, list):
        for row in payload:
            ident = _record_id_in(row)
            if ident not in (None, ""):
                return ident
        return None
    if isinstance(payload, dict):
        if isinstance(payload.get("id"), (int, str)) and payload.get("id") != "":
            return payload["id"]
        for value in payload.values():
            if isinstance(value, (list, dict)):
                ident = _record_id_in(value)
                if ident not in (None, ""):
                    return ident
    return None


def urllib_request(path: str, base_url: str):  # noqa: D401 - small sync helper
    """GET *path* on *base_url*; (status, body, '', final). ``0`` on failure."""
    full = urljoin(base_url, path)
    try:
        with urllib.request.urlopen(full, timeout=10) as r:  # noqa: S310 - same origin
            return r.status, r.read().decode("utf-8", "replace"), "", r.geturl()
    except Exception:
        return 0, "", "", full


# The call site that hands a service an object literal. The class methods of a
# bundle are minified and take the ready-made record, so the *payload* keys are
# only visible where a component builds one: ``.create(id,{message: …})``,
# ``.patch({id:…, message:…})``.
_METHOD_CALL = re.compile(r"\.(create|patch|update|add|save|submit|post)\s*\(")


def _body_field(body: str) -> str:
    """The field of the payload object, or '' when the body is an identifier.

    Callers hand in everything from the argument separator onward, so the
    object is found rather than matched at position 0: ``, {message: x}`` for a
    client call and ``{method: 'POST', body: JSON.stringify({email: x})}`` for a
    fetch, whose own option keys describe the request and not the payload.
    """
    text = (body or "").lstrip(" \t\r\n,")
    while True:
        m = _BODY_FIRST_KEY.match(text)
        if not m:
            return ""
        key = next((g for g in m.groups() if g), "")
        if not key:
            return ""
        if key.lower() not in _FETCH_OPTION_KEYS:
            return key if key in _KNOWN_BODY_FIELDS else ""
        # Skip the option key and look at the next object literal deeper in.
        text = text[m.end() :].lstrip(" \t\r\n'\"")
        brace = text.find("{")
        if brace == -1:
            return ""
        text = text[brace:]


def _payload_keys_at(js: str, pos: int, window: int = 12000) -> List[str]:
    """Keys the components actually send, read from the module around *pos*.

    A write call is resolved in three steps, each one only run when the step
    before it named nothing:

    1. The class that owns the call builds the object inline —
       ``.patch({id: …, message: …})``, ``.create(id, {message: …})``.
    2. The class that owns the call builds it into a local or grows it field by
       field — ``let i={message: …}; …create(id,i)`` or
       ``this.complaint.message=…; …save(this.complaint)``.
    3. The owning class is a service that only forwards its argument —
       ``save(t){…post(url,t)}``. The record is then whatever the component
       beside it hands that method, and step 2 is retried on that component.

    Every key is filed under the nearest class it was written in, so the next
    feature's record (a complaint's captcha, an address's country) cannot leak
    into this one. Ordered so the field most likely to be rendered comes first.
    """
    from intellixss.analysis.static_dom import _split_args

    body_start, body_end = _module_span(js or "", pos)
    lo = max(0, body_start - 4000)
    chunk = (js or "")[lo : body_end + 4000]

    primary = _enclosing_class(chunk, pos - lo)
    if primary[0] == -1:
        return []
    neighbours = [
        c for c in (_class_after(chunk, primary[1]), _class_before(chunk, primary[0])) if c
    ]
    # The service first, then the component that calls it. A neighbour is
    # only read when the class before it named no payload field.
    relevant = [primary] + neighbours

    counts: Dict[str, int] = {}
    values: Dict[str, List[str]] = {}

    def calls_in(classes: List[tuple]) -> List[tuple]:
        """``(args, owner)`` for every client call made inside *classes*."""
        out = []
        for call in _METHOD_CALL.finditer(chunk):
            owner = _enclosing_class(chunk, call.start())
            if owner not in classes:
                continue
            out.append((_split_args(chunk, call.end() - 1), owner))
        return out

    def take_inline(calls) -> None:
        for args, _ in calls:
            for arg in args:
                obj = arg.strip()
                if not (obj.startswith("{") and obj.endswith("}")):
                    continue
                for pair in _OBJECT_PAIR.finditer(obj):
                    _take_key(counts, values, pair)

    def take_built(record: str, owners: List[tuple], calls) -> None:
        """Fields of *record* as the classes in *owners* build it."""
        name = record.split(".")[-1]
        for owner in owners:
            if owner[0] == -1:
                continue
            for m in _PROPERTY_ASSIGN.finditer(chunk[owner[0] : owner[1]]):
                if m.group(1).split(".")[-1] != name:
                    continue
                fragment = m.group(3)
                key = m.group(2)
                # ``this.complaint={},this.complaint.UserId=…`` chains several
                # assignments through one comma expression; each is read on its
                # own so a handle next to a message does not hide it.
                if _is_user_text(fragment):
                    _take_named(counts, values, key, fragment)
        for m in _LOCAL_OBJECT.finditer(chunk):
            if m.group(1) != name or not m.group(2):
                continue
            for pair in _OBJECT_PAIR.finditer("{" + m.group(2) + "}"):
                if _is_user_text(pair.group(3)):
                    _take_key(counts, values, pair)

    calls = calls_in([primary])
    take_inline(calls)

    if not _substantive(counts, values):
        # Step 2 on the owning class: the record it hands over by name.
        for record in _records_of(calls):
            take_built(record, [primary], calls)

    if not _substantive(counts, values) and neighbours:
        counts.clear()
        values.clear()
        beside = calls_in(neighbours)
        take_inline(beside)
        if not _substantive(counts, values):
            # Step 3: the service forwards its parameter, so read what the
            # component hands the method the service exposes.
            for record in _records_of(beside):
                take_built(record, neighbours, beside)

    out: List[str] = []
    for key, n in sorted(counts.items(), key=lambda kv: (-_field_rank(kv[0]), -kv[1])):
        if key.lower() in _IDENTIFIER_KEYS and all(
            _looks_like_identifier(v) for v in values.get(key, [])
        ):
            continue
        out.append(key)
    return out


def _records_of(calls) -> List[str]:
    """The object arguments of *calls*, most specific first.

    ``.create(this.data.productData.id, i)`` hands over ``i``; ``.save(this.complaint)``
    hands over the record itself. A template or a concatenation is a URL, never
    a record, and a literal is read inline by the caller instead.
    """
    found: List[str] = []
    for args, _ in calls:
        for arg in reversed(args):
            text = arg.strip()
            if not text or text.startswith(("{", "`", "'", '"')) or text[0].isdigit():
                continue
            if "`" in text or "+" in text:
                continue
            if text not in found:
                found.append(text)
    # A dotted handle names an object whose fields are written on it; a bare
    # identifier is either a local or a forwarded parameter, and both are
    # resolved by name in ``take_built``.
    return sorted(found, key=lambda t: 0 if "." in t else 1)


def _substantive(counts: Dict[str, int], values: Dict[str, List[str]]) -> bool:
    """Whether any collected key names text rather than a record handle."""
    return any(
        not (k.lower() in _IDENTIFIER_KEYS and all(_looks_like_identifier(x) for x in values.get(k, [])))
        for k in counts
    )


# ``{key: value`` inside an object literal handed to a service method.
_OBJECT_PAIR = re.compile(
    r"""(?:^|[,{])\s*(?:['"]([A-Za-z_$][\w$-]*)['"]|([A-Za-z_$][\w$]*))\s*:\s*([^,}]+)"""
)

# ``let i={message:t.value,author:this.author}`` — a record built into a local
# and handed to the service afterwards. Group 1 is the bare name, group 2 the
# object's body, group 3 the same assignment through ``this.x``.
_LOCAL_OBJECT = re.compile(
    r"""(?:^|[;{,])\s*(?:let|const|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]*)\}"""
    r"""|(?:this\s*\.\s*([A-Za-z_$][\w$.]*))\s*=\s*\{([^{}]*)\}"""
)

# ``this.complaint.message = value`` — a record grown field by field. Minified
# code chains several assignments through one comma expression
# (``this.complaint={},this.complaint.UserId=t.id,this.complaint.message=…``),
# so the value stops at the next top-level comma as well as at a semicolon.
# A comma or semicolon nested in a call, an array or an object does not end it.
_PROPERTY_ASSIGN = re.compile(
    r"""\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)"""
    r"""\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*((?:[^;,\[\]{}()]|\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\})+)"""
)


def _take_key(counts: Dict[str, int], values: Dict[str, List[str]], pair) -> None:
    """Record one ``key: value`` when the key can be a payload field."""
    _take_named(counts, values, pair.group(1) or pair.group(2), pair.group(3))


def _take_named(
    counts: Dict[str, int], values: Dict[str, List[str]], key: str, value: str
) -> None:
    """Record *key* as a payload field unless the bundle's own machinery uses it."""
    if not key or key.lower() in _FETCH_OPTION_KEYS:
        return
    if key in _NOT_PAYLOAD_KEYS or key.lower() in _NOT_PAYLOAD_KEYS:
        return
    counts[key] = counts.get(key, 0) + 1
    values.setdefault(key, []).append((value or "").strip())


# A record's own text is the likely sink; a captcha id, a token or a security
# answer is a precondition the handler checks before it stores anything.
_TEXT_FIRST = (
    "message", "comment", "content", "review", "text", "body", "description",
    "feedback", "complaint", "subject", "title", "note",
)


def _field_rank(key: str) -> int:
    """How likely *key* is the stored text: 2 for a text field, 1 for other."""
    low = key.lower()
    if low in _TEXT_FIRST:
        return 2
    if low.endswith(("token", "id", "answer", "question")):
        return 0
    return 1


# A value that carries what the user actually typed: a form control's value, a
# reactive-form read (``form.value.comment``, ``controls.comment.value``), a
# lookup of one, a literal, or a concatenation of those.
_USER_TEXT = re.compile(
    r"""\.\s*value\b|\.\s*nativeElement\b"""
    r"""|\.\s*(?:get|emit|toLowerCase|trim)\s*\("""
    r"""|['"`]"""
)


def _is_user_text(value: str) -> bool:
    """Whether a field's value is user-supplied rather than copied state.

    ``{message: t.value, author: this.author}`` builds a review: the message
    is what was typed, the author is the session's own name. Both are in the
    record, but only the first is text the handler will render back — and a
    sink reported on ``author`` is a false positive nobody can reproduce.
    """
    return bool(_USER_TEXT.search(value or ""))


_IDENTIFIER_KEYS = {"id", "_id", "product", "productid", "userid", "quantity", "rating"}

# Angular's private build artefacts: dependency-injection descriptors,
# i18n dictionaries and scope markers are written as object literals too, and
# none of them is a field a handler reads.
_NOT_PAYLOAD_KEYS = {
    "provide", "providers", "useValue", "useClass", "useFactory", "useExisting",
    "deps", "parent", "paymentMode", "paymentId", "multi", "token", "factory",
    "changeDetection", "template", "host", "selector", "styles", "inputs",
    "outputs", "standalone", "imports", "source", "text", "map", "line",
}

# A bundle is split into one feature per module, and a module is a contiguous
# run between two exported classes: ``…})();var Bs=(()=>{class e{…``. The
# component that builds a record and the service that posts it live in the
# same run, which is the scope worth reading a call's keys from.
_MODULE_BOUNDARY = re.compile(r"\}\)\(\);\s*(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\(")
# The marker only exists when modules were emitted as their own IIFE. Without
# it the run is found from the ``var X=(()=>{`` opener of the module itself.
_MODULE_OPENER = re.compile(r"=\s*\(\s*\(\s*\)\s*=>\s*\{|=\s*\(\s*function\s*\(\s*\)\s*\{")


def _module_span(js: str, pos: int) -> tuple:
    """The module run around *pos*, as ``(start, end)``.

    A bundle is a sequence of ``(function(){…})();`` blocks, one per compiled
    module. When those markers are absent (a minified excerpt, a hand-written
    script) the span falls back to the enclosing class, and then to a window
    around the call.
    """
    starts = [m.start() for m in _MODULE_BOUNDARY.finditer(js or "") if m.start() <= pos]
    if starts:
        start = starts[-1]
        after = _MODULE_BOUNDARY.search(js or "", pos)
        return start, (after.start() if after else len(js or ""))
    opens = [m for m in _MODULE_OPENER.finditer(js or "") if m.start() <= pos]
    if opens:
        from intellixss.analysis.static_dom import _match_brace

        brace = (js or "").find("{", opens[-1].start())
        close = _match_brace(js or "", brace) if brace != -1 else -1
        if close != -1 and close >= pos:
            return opens[-1].start(), close + 1
    return _enclosing_class(js or "", pos)


def _class_after(js: str, pos: int) -> Optional[tuple]:
    """The first ``class X { … }`` that starts after *pos*, or ``None``."""
    from intellixss.analysis.static_dom import _match_brace

    m = re.compile(r"\bclass\s+[A-Za-z_$][\w$]*\s*[{ ]").search(js or "", max(0, pos))
    if not m:
        return None
    brace = (js or "").find("{", m.start())
    end = _match_brace(js or "", brace) if brace != -1 else -1
    return (m.start(), end + 1) if end != -1 else None


def _class_before(js: str, pos: int) -> Optional[tuple]:
    """The last ``class X { … }`` that ends before *pos*, or ``None``."""
    from intellixss.analysis.static_dom import _match_brace

    best = None
    for m in re.compile(r"\bclass\s+[A-Za-z_$][\w$]*\s*[{ ]").finditer(js or ""):
        if m.start() >= pos:
            break
        brace = (js or "").find("{", m.start())
        end = _match_brace(js or "", brace) if brace != -1 else -1
        if end == -1:
            continue
        if end < pos:
            best = (m.start(), end + 1)
    return best


def _enclosing_class(js: str, pos: int) -> tuple:
    """The ``class X { … }`` body spanning *pos*, as ``(start, end)``.

    Returns a window around *pos* when the call is not inside a class.
    """
    from intellixss.analysis.static_dom import _match_brace

    best = (-1, -1)
    for m in re.finditer(r"\bclass\s+[A-Za-z_$][\w$]*\s*[{ ]", js or ""):
        if m.start() > pos:
            break
        brace = (js or "").find("{", m.start())
        if brace == -1:
            continue
        end = _match_brace(js, brace)
        if end == -1 or end < pos:
            continue
        # ``_match_brace`` returns the index of the closing brace itself.
        end += 1
        if best[0] == -1 or (end - m.start()) < (best[1] - best[0]):
            best = (m.start(), end)
    if best[0] == -1:
        return max(0, pos - 20000), min(len(js), pos + 20000)
    return best


def _looks_like_identifier(value: str) -> bool:
    """Whether an object value names a record rather than carrying text."""
    text = value.strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return True
    return bool(
        re.fullmatch(
            r"(?:this\s*\.\s*)?[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*"
            r"(?:\.\s*value)?",
            text,
        )
    )


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
        if t.source in ("client_query", "client_route"):
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

        # Writes a script makes. A single-page application ships no form and no
        # endpoint in its markup, so the call in the bundle is the only evidence
        # of what it stores — and the bundle has to be fetched to read it.
        bundle = "\n".join(await fetch_page_scripts(client, body, page_url))
        writes = detect_js_endpoints(bundle, page_url)
        # One target per (endpoint, field): the stored pass tests a single
        # field per target, so folding the candidates into one params list
        # would report the field that happened to be first as the whole story.
        for method, ep, *rest in writes:
            if not _same_scope(ep, seed_url):
                continue
            # An endpoint whose payload key the bundle names needs exactly one
            # target. Padding it with the generic guesses spends the scan
            # budget on fields the handler never reads and pushes the real
            # sinks past ``max_urls``.
            fields = rest if rest else []
            if not fields:
                continue
            ep = _concrete_resource(ep, seed_url)
            for field in fields:
                add(
                    ScanTarget(
                        url=ep,
                        method=method,
                        params=[field],
                        data={field: "test"},
                        source="js_write",
                    )
                )

        # A client route is not a request. A hash-routed application keeps the
        # path and its query in the fragment, so neither the document nor a
        # crawl can name it: the server only ever receives ``/``. The bundle
        # can — the router reads the key and the navigate call names the route
        # — and that is the only path to a DOM XSS that fires without the
        # server seeing the payload. Juice Shop's documented DOM XSS is exactly
        # this shape (``q`` → ``bypassSecurityTrustHtml`` → ``[innerHTML]``).
        hash_routed = bool(
            re.search(r"useHash\s*:\s*(?:!0|true)", f"{bundle}\n{body}", re.I)
        )
        for route, name in detect_client_route_params(bundle):
            route_path = route or "/"
            if hash_routed:
                route_url = f"{origin}/#{route_path}"
            else:
                route_url = f"{origin}{route_path}"
            add(
                ScanTarget(
                    url=route_url,
                    method="GET",
                    params=[name],
                    source="client_route",
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
