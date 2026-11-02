"""Parameter mining: candidate names a page might read but never links to.

A reflected parameter is only reachable if its name is known. Dalfox and Arjun
close that gap with a dictionary; this module does that *and* reads names out of
the page itself, which a static wordlist cannot — a field the app genuinely
consumes is far stronger evidence than a guess, and it costs the same single
canary request to confirm.

Everything here is a *candidate*. Nothing is ever reported from mining alone:
the caller sends each name with a unique canary and keeps it only when the
canary is reflected and the response actually changed (see
``_guess_reflected_params`` in ``discovery.targets``). So mining widely is safe
— a name the handler ignores is dropped, it is not a finding. The only cost of
a bad candidate is one request, which is why the lists below are bounded.
"""

from __future__ import annotations

import re
from typing import List
from urllib.parse import parse_qsl, urlsplit

# A legal parameter-name token. Deliberately strict: mining reads from markup
# and minified JS, both full of noise, so anything that is not plausibly a
# parameter name is rejected before it can cost a request.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,39}$")

# Query strings anywhere in the body: links, form actions, JS string literals.
# The app writing ``?returnUrl=`` into a link is proof it reads ``returnUrl``.
_QS_IN_TEXT = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,39})=")

# ``name="x"`` / ``id="x"`` on form controls — a field that posts or seeds a GET.
_ATTR_NAME = re.compile(
    r"<(?:input|textarea|select|button)\b[^>]*?\b(?:name|id)\s*=\s*['\"]?"
    r"([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,39})",
    re.I,
)

# JS reads of a named request parameter. Each group 1 is the parameter name the
# code pulls out of the URL — the strongest client-side signal there is.
_JS_PARAM_READS = [
    # URLSearchParams / params.get('x'), .getAll('x'), .has('x')
    re.compile(r"\.(?:get|getAll|has)\s*\(\s*['\"]([A-Za-z_][\w.\-]{0,39})['\"]"),
    # getParameterByName('x') and friends
    re.compile(r"[Gg]etParameter(?:ByName)?\s*\(\s*['\"]([A-Za-z_][\w.\-]{0,39})['\"]"),
    # server frameworks leaking names into inline script / comments
    re.compile(r"\$_(?:GET|REQUEST|POST)\[\s*['\"]([A-Za-z_][\w.\-]{0,39})['\"]"),
    re.compile(r"request\.args\.get\s*\(\s*['\"]([A-Za-z_][\w.\-]{0,39})['\"]"),
    re.compile(r"\breq\.query\.([A-Za-z_][\w]{0,39})"),
]

# Names whose value is request machinery or an opaque identifier, not user
# content: injecting them breaks the request rather than reflecting, so the
# budget must never be spent on them. Kept deliberately small — only tokens that
# can *never* be a usable reflected-XSS target — so legitimate parameters such
# as ``content`` or ``type`` are not filtered out by accident.
_NOISE = {
    "csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken", "_token",
    "authenticity_token", "token", "nonce", "captcha", "g-recaptcha-response",
    "id", "uuid", "guid", "_", "callback",  # jsonp callback is its own plugin
    "submit", "charset", "viewport",
}

# A compact, high-yield dictionary of names that are commonly reflected and
# commonly unlinked. Trimmed to reflection-prone parameters (search, message,
# redirect, template, debug surfaces) rather than a generic crawl list, so the
# guess pass stays cheap. Ordered roughly by how often each actually reflects.
# Names in ``_NOISE`` are intentionally absent so the two never collide.
COMMON_PARAMS: tuple = (
    "q", "s", "search", "query", "keyword", "keywords", "term", "p",
    "name", "message", "msg", "comment", "text", "title", "subject", "body",
    "content", "description", "desc", "value", "data", "input", "field",
    "redirect", "redirect_url", "redirect_uri", "return", "returnUrl",
    "return_url", "returnTo", "next", "url", "uri", "link", "goto", "dest",
    "destination", "continue", "r", "u", "page", "view", "file", "path",
    "lang", "language", "locale", "country", "ref", "referrer", "source",
    "utm_source", "callback_url", "template", "tpl", "theme", "skin",
    "debug", "test", "error", "err", "mode", "action", "cmd", "do", "func",
    "email", "user", "username", "login", "to", "from", "cc", "tag", "category",
    "filter", "sort", "order", "type", "format", "output",
)


def _ranked_unique(groups: List[List[str]]) -> List[str]:
    """Flatten name groups, lowercasing for dedupe, keeping first-seen order.

    Earlier groups rank higher: a name the page's own query strings use beats a
    form field name, which beats a JS read, which beats a dictionary guess.
    """
    seen: set = set()
    out: List[str] = []
    for group in groups:
        for raw in group:
            name = raw.strip()
            if not name or not _NAME_RE.match(name):
                continue
            key = name.lower()
            if key in _NOISE or key in seen:
                continue
            seen.add(key)
            out.append(name)
    return out


def mine_param_names(html: str, limit: int = 40) -> List[str]:
    """Candidate parameter names read out of a page's markup and inline JS.

    Ranked by signal strength and de-duplicated. These are evidence drawn from
    the target itself; the caller still proves each with a canary before it is
    scanned, so a wrong guess here costs one request, never a false finding.
    """
    if not html:
        return []

    qs_names = _QS_IN_TEXT.findall(html)
    field_names = _ATTR_NAME.findall(html)
    js_names: List[str] = []
    for pat in _JS_PARAM_READS:
        js_names.extend(pat.findall(html))

    ranked = _ranked_unique([qs_names, field_names, js_names])
    return ranked[:limit]


def candidate_params(
    html: str,
    include_wordlist: bool = True,
    mine_limit: int = 40,
    wordlist_limit: int = 30,
) -> List[str]:
    """Full ordered candidate list: mined-from-page names first, then dictionary.

    Mined names come first because they are evidence; the dictionary fills in
    the conventional names the page never reveals. The caller bounds how many it
    will actually send — this just orders them so the highest-signal names are
    tried first and the budget is spent where it is most likely to pay off.
    """
    groups = [mine_param_names(html, limit=mine_limit)]
    if include_wordlist:
        groups.append(list(COMMON_PARAMS[:wordlist_limit]))
    return _ranked_unique(groups)
