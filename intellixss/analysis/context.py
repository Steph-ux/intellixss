"""Injection context detection — HTML5-aware state machine (pure).

The previous implementation guessed the context from ``rfind("<")`` and quote
counting in a character window. That breaks on:

  * ``<script>`` blocks containing ``"`` inside strings/regexes
  * attributes split across newlines
  * ``<!-- -->`` comments that contain tags
  * textarea/title raw-text elements
  * unquoted attribute values followed by a ``>`` inside the value

This module walks the document once, in HTML parsing order, carrying an
explicit state (data / tag-open / attribute / raw-text / comment / script-js)
and *stops* on the marker. The state at the stop point is the injection
context — no heuristics over a truncated window.

Public API
----------
``analyze_marker(html, marker) -> ContextHit``
    Full analysis: context, enclosing tag/attribute, quote character,
    preceding JS tokens (for string breakouts) and reflection offsets.

``detect_context(html, marker) -> InjectionContext``
    Backward-compatible thin wrapper.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from intellixss.models import InjectionContext

_WS = " \t\n\r\f"
# Raw text elements: content is not parsed as markup until the close tag.
_RAW_TEXT = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes"}

# Attributes whose value is a URL → javascript:/data: are live vectors.
_URL_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster", "cite",
    "background", "longdesc", "srcset", "xlink:href", "manifest", "codebase",
}

_JS_HINT_ATTRS = {
    "onload", "onerror", "onclick", "onfocus", "onmouseover", "onmouseout",
    "onmouseenter", "onmouseleave", "onkeyup", "onkeydown", "onkeypress",
    "onsubmit", "onchange", "oninput", "ontoggle", "onanimationend",
    "onanimationstart", "ontransitionend", "onpageshow", "onhashchange",
    "onpointerover", "onpointerenter", "onpointerdown", "ondrag", "ondrop",
    "onwheel", "onscroll", "onbeforetoggle", "onfocusin", "onmousedown",
}


@dataclass
class ContextHit:
    """Rich result of ``analyze_marker``."""

    context: InjectionContext = InjectionContext.UNKNOWN
    tag_name: str = ""
    attr_name: str = ""
    quote_char: str = ""  # '"', "'" or "" (unquoted/not applicable)
    # JS state (script / event handler) — used to build breakouts
    js_string_quote: str = ""  # the quote that opened the current string
    js_before: str = ""  # up to 120 chars of JS source before the marker
    js_is_regex: bool = False
    in_url_attr: bool = False
    confidence: float = 0.6
    notes: List[str] = field(default_factory=list)
    # Offsets of every occurrence of the marker in the source
    occurrences: List[Tuple[int, int]] = field(default_factory=list)
    # Start offset of the occurrence this hit was classified from. Callers that
    # re-measure the same injection point in another response need this to
    # identify which echo they are talking about.
    chosen_pos: int = -1
    # True when the echo only exists as escaped source text: the marker is
    # still there, but the delimiters around it arrived as ``&lt;``/``&quot;``.
    # A value that survives in that form is stored-and-encoded, never live.
    encoded: bool = False

    @property
    def payload_quote(self) -> str:
        """The quote a payload must use to close the *injected* string.

        Two different quotes are in play and confusing them silently breaks
        every breakout: ``quote_char`` is the HTML attribute delimiter
        (``onload="…"``), while the JS string inside it may be opened with the
        other one (``startTimer('…')``). Payload templates marked ``Q`` need
        the JS one, so prefer it whenever the walker recorded it.
        """
        if self.context in (
            InjectionContext.JS_STRING_SINGLE,
            InjectionContext.JS_STRING_DOUBLE,
            InjectionContext.JS_TEMPLATE,
            InjectionContext.JS_IN_ATTR,
            InjectionContext.JS_CODE,
        ) and self.js_string_quote in ("'", '"'):
            return self.js_string_quote
        return self.quote_char

    def to_dict(self) -> dict:
        return {
            "context": self.context.value,
            "context_label": self.context.label,
            "tag_name": self.tag_name,
            "attr_name": self.attr_name,
            "quote_char": self.quote_char,
            "js_string_quote": self.js_string_quote,
            "in_url_attr": self.in_url_attr,
            "confidence": round(self.confidence, 2),
            "notes": self.notes,
            "occurrences": len(self.occurrences),
        }


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def detect_context(html_body: str, marker: str) -> InjectionContext:
    """Return the injection context of *marker* inside *html_body*."""
    return analyze_marker(html_body, marker).context


def find_all(haystack: str, needle: str, case_insensitive: bool = False) -> List[Tuple[int, int]]:
    """All (start, end) offsets of *needle* in *haystack*."""
    if not haystack or not needle:
        return []
    out: List[Tuple[int, int]] = []
    hay = haystack.lower() if case_insensitive else haystack
    ndl = needle.lower() if case_insensitive else needle
    start = 0
    while True:
        idx = hay.find(ndl, start)
        if idx == -1:
            return out
        out.append((idx, idx + len(ndl)))
        start = idx + max(1, len(ndl) // 2)


def analyze_marker(html: str, marker: str, limit_occurrences: int = 32) -> ContextHit:
    """
    Locate *marker* and classify the parser state at that position.

    When the marker appears several times we pick the *best* (most promising)
    context rather than the first: a reflection inside ``<script>`` is more
    interesting than the same string echoed in a footer text node.
    """
    if not html or not marker:
        return ContextHit(
            context=InjectionContext.UNKNOWN,
            confidence=0.0,
            notes=["empty html or marker"],
        )

    occurrences = find_all(html, marker, case_insensitive=True)[:limit_occurrences]
    if not occurrences:
        return ContextHit(
            context=InjectionContext.UNKNOWN,
            confidence=0.0,
            notes=["marker not found"],
        )

    best: Optional[ContextHit] = None
    best_start = -1
    for start, end in occurrences:
        hit = _analyze_at(html, marker, start, end)
        hit.chosen_pos = start
        if best is None or _promise(hit) > _promise(best):
            best = hit
            best_start = start
        # An executable-by-construction context is a definitive answer.
        if hit.context in (
            InjectionContext.JS_CODE,
            InjectionContext.JS_STRING_DOUBLE,
            InjectionContext.JS_STRING_SINGLE,
            InjectionContext.JS_TEMPLATE,
            InjectionContext.JS_IN_ATTR,
            InjectionContext.HTML_ATTR_DOUBLE,
            InjectionContext.HTML_ATTR_SINGLE,
            InjectionContext.HTML_ATTR_UNQUOTED,
            InjectionContext.HTML_ATTR_HREF,
            InjectionContext.ENTITY_ENCODED_TAG,
        ):
            break

    assert best is not None
    best.occurrences = occurrences
    best.chosen_pos = best_start
    best.notes.append(f"{len(occurrences)} reflection(s) of marker")
    return best


def _promise(hit: ContextHit) -> float:
    order = {
        InjectionContext.HTML_ATTR_HREF: 9.0,
        InjectionContext.ENTITY_ENCODED_TAG: 8.9,
        InjectionContext.JS_IN_ATTR: 8.8,
        InjectionContext.JS_STRING_SINGLE: 8.6,
        InjectionContext.JS_STRING_DOUBLE: 8.6,
        InjectionContext.JS_TEMPLATE: 8.4,
        InjectionContext.JS_CODE: 8.2,
        InjectionContext.HTML_ATTR_DOUBLE: 8.0,
        InjectionContext.HTML_ATTR_SINGLE: 8.0,
        InjectionContext.HTML_ATTR_UNQUOTED: 7.4,
        InjectionContext.TEXTAREA: 6.0,
        InjectionContext.TITLE: 6.0,
        InjectionContext.HTML_COMMENT: 4.0,
        InjectionContext.CSS_VALUE: 3.2,
        InjectionContext.JSON_VALUE: 3.0,
        InjectionContext.HTML_TEXT: 5.0,
        InjectionContext.SCRIPT_TAG: 7.0,
        InjectionContext.URL_FRAGMENT: 7.8,
        InjectionContext.UNKNOWN: 0.0,
    }
    return order.get(hit.context, 0.0)


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

# Parser states
_DATA = "data"
_TAG_NAME = "tag_name"
_BEFORE_ATTR = "before_attr"
_ATTR_NAME = "attr_name"
_AFTER_ATTR_NAME = "after_attr_name"
_BEFORE_VALUE = "before_value"
_ATTR_VALUE_DQ = "attr_value_dq"
_ATTR_VALUE_SQ = "attr_value_sq"
_ATTR_VALUE_UNQ = "attr_value_unq"
_COMMENT = "comment"
_DOCTYPE = "doctype"
_RAW = "raw"  # inside script/style/textarea/...
_END_TAG = "end_tag"


def _analyze_at(html: str, marker: str, start: int, end: int) -> ContextHit:
    """Walk the document up to *start* and return the state hit."""
    hit = ContextHit()
    ctx, tag, attr, quote, js_quote, js_text = _walk(html, start, entity_encoded=False)
    hit.context, hit.tag_name, hit.attr_name, hit.quote_char = ctx, tag, attr, quote
    if ctx in (InjectionContext.JS_IN_ATTR, InjectionContext.JS_STRING_SINGLE,
               InjectionContext.JS_STRING_DOUBLE, InjectionContext.JS_TEMPLATE,
               InjectionContext.JS_CODE):
        hit.js_string_quote = js_quote
        hit.js_before = "".join(js_text[-120:])
    if ctx == InjectionContext.HTML_ATTR_HREF:
        hit.in_url_attr = True

    if ctx == InjectionContext.ENTITY_ENCODED_TAG:
        # The marker sits inside a tag whose delimiter characters were
        # HTML-encoded by the app (&lt;img … &gt;). Browsers decode entities on
        # *some* paths (innerHTML, template engines), so the enclosing tag is
        # re-parsed in decoded mode to learn where the data actually lands.
        hit.encoded = True
        ctx2, tag2, attr2, quote2, _q2, _t2 = _walk(html, start, entity_encoded=True)
        hit.notes.append(
            f"enclosing <{tag}> is entity-encoded; decoded parse lands in "
            f"{ctx2.label}"
        )
        if ctx2 != InjectionContext.ENTITY_ENCODED_TAG:
            hit.context, hit.tag_name = ctx2, tag2 or tag
            hit.attr_name, hit.quote_char = attr2, quote2
    return hit


def _walk(
    html: str, start: int, entity_encoded: bool
) -> Tuple[InjectionContext, str, str, str, str, List[str]]:
    """Run the parser from 0 to *start*.

    Returns ``(context, tag, attr, quote, js_quote, js_text)``. The last two
    carry the JS lexical state for script bodies / event-handler attributes so
    callers can build a quote-aware breakout payload.
    """
    n = len(html)
    i = 0
    state = _DATA

    tag_name = ""
    attr_name = ""
    quote = ""
    encoded_tag = ""
    # Raw-text element bookkeeping
    raw_name = ""
    raw_is_js = False

    # --- JS sub-state (only meaningful inside <script> or on*= handlers) ---
    js_quote = ""  # currently open JS string quote
    js_text: List[str] = []  # collected JS source before marker
    js_in_regex = False
    js_in_line_comment = False
    js_in_block_comment = False
    # URL-attribute probe: does the value start with javascript:?
    url_scan_attr = ""  # attribute whose value is being scanned
    pseudo_probe = ""  # value text seen so far, for the prefix test
    pseudo_state = 2  # 0 unknown, 1 javascript: confirmed, 2 not javascript:
    def push_js(ch: str) -> None:
        js_text.append(ch)

    while i < start and i < n:
        ch = html[i]

        if state == _COMMENT:
            if html.startswith("-->", i):
                state = _DATA
                i += 3
                continue
            i += 1
            continue

        if state == _DOCTYPE:
            if ch == ">":
                state = _DATA
            i += 1
            continue

        if state == _RAW:
            if html.startswith("</", i):
                m = re.match(r"</\s*([a-zA-Z0-9]+)", html[i:])
                if m and m.group(1).lower() == raw_name:
                    state = _DATA
                    i += m.end()
                    continue
            if raw_is_js:
                # Track JS lexical state char by char.
                nxt = html[i + 1] if i + 1 < n else ""
                if js_in_block_comment:
                    if ch == "*" and nxt == "/":
                        js_in_block_comment = False
                        push_js("*/")
                        i += 2
                        continue
                    push_js(ch)
                    i += 1
                    continue
                if js_in_line_comment:
                    push_js(ch)
                    if ch == "\n":
                        js_in_line_comment = False
                    i += 1
                    continue
                if js_in_regex:
                    if ch == "\\":
                        push_js(ch)
                        if nxt:
                            push_js(nxt)
                        i += 2
                        continue
                    if ch == "/":
                        js_in_regex = False
                    elif ch == "\n":
                        # Unterminated regex — treat as division, not a literal
                        js_in_regex = False
                    push_js(ch)
                    i += 1
                    continue
                if js_quote:
                    if ch == "\\":
                        push_js(ch)
                        if nxt:
                            push_js(nxt)
                        i += 2
                        continue
                    if ch == js_quote:
                        js_quote = ""
                    elif js_quote == "`" and ch == "$" and nxt == "{":
                        # Template interpolation switches to code for one level.
                        # Track nesting so `}` returns to the string.
                        depth = 1
                        j = i + 2
                        while j < n and depth > 0:
                            if html[j] == "{":
                                depth += 1
                            elif html[j] == "}":
                                depth -= 1
                            j += 1
                        push_js("".join(html[i : min(j, start)]))
                        i = j
                        js_quote = "`"
                        continue
                    push_js(ch)
                    i += 1
                    continue
                if ch == "/" and nxt == "/":
                    js_in_line_comment = True
                    push_js("//")
                    i += 2
                    continue
                if ch == "/" and nxt == "*":
                    js_in_block_comment = True
                    push_js("/*")
                    i += 2
                    continue
                if ch == "/" and _regex_allowed(js_text):
                    # Division vs regex literal is decided by the previous token.
                    js_in_regex = True
                    push_js(ch)
                    i += 1
                    continue
                if ch in ("'", '"', "`"):
                    js_quote = ch
                    push_js(ch)
                    i += 1
                    continue
                push_js(ch)
                i += 1
                continue
            i += 1
            continue

        if state == _DATA:
            if html.startswith("<!--", i):
                state = _COMMENT
                i += 4
                continue
            if html.startswith("<![CDATA[", i):
                close = html.find("]]>", i)
                i = n if close == -1 else close + 3
                continue
            if ch == "<":
                if html.startswith("<!", i):
                    state = _DOCTYPE
                    i += 2
                    continue
                if html.startswith("</", i):
                    state = _END_TAG
                    i += 2
                    continue
                nxt = html[i + 1] if i + 1 < n else ""
                if nxt.isalpha():
                    prev_ch = html[i - 1] if i > 0 else ""
                    if entity_encoded and not prev_ch.isalnum():
                        # ``&lt;`` was decoded: the browser opened a tag here.
                        state = _TAG_NAME
                        tag_name = ""
                        i += 1
                        continue
                    if not entity_encoded:
                        # A raw ``<tag`` that never closes before the marker
                        # is the tag the reflection lands inside.
                        state = _TAG_NAME
                        tag_name = ""
                        i += 1
                        continue
                    # Track the last *encoded* ``&lt;name`` so a marker landing
                    # inside it is reported as an entity-encoded tag rather
                    # than as HTML text.
                    m = re.match(r"&lt;([a-zA-Z][a-zA-Z0-9]*)", html[i:])
                    if m:
                        encoded_tag = m.group(1).lower()
                        if "<" not in html[i : start] and "&lt;" not in html[m.end() : start]:
                            return (
                                InjectionContext.ENTITY_ENCODED_TAG,
                                encoded_tag,
                                "",
                                "",
                            )
                    i += 1
                    continue
                i += 1
                continue
            i += 1
            continue

        if state == _END_TAG:
            if ch == ">":
                state = _DATA
            i += 1
            continue

        if state == _TAG_NAME:
            if ch in _WS:
                state = _BEFORE_ATTR
                i += 1
                continue
            if ch == ">":
                if _enter_tag_body(tag_name):
                    state = _RAW
                    raw_name = tag_name.lower()
                    raw_is_js = raw_name == "script"
                else:
                    state = _DATA
                i += 1
                continue
            if ch == "/":
                state = _BEFORE_ATTR
                i += 1
                continue
            tag_name += ch
            i += 1
            continue

        if state == _BEFORE_ATTR:
            if ch in _WS or ch == "/":
                i += 1
                continue
            if ch == ">":
                if _enter_tag_body(tag_name):
                    state = _RAW
                    raw_name = tag_name.lower()
                    raw_is_js = raw_name == "script"
                else:
                    state = _DATA
                i += 1
                continue
            state = _ATTR_NAME
            attr_name = ""
            continue

        if state == _ATTR_NAME:
            if ch in _WS:
                state = _AFTER_ATTR_NAME
                i += 1
                continue
            if ch == "=":
                state = _BEFORE_VALUE
                i += 1
                continue
            if ch in "/>":
                state = _BEFORE_ATTR
                attr_name = ""
                i += 1
                continue
            attr_name += ch
            i += 1
            continue

        if state == _AFTER_ATTR_NAME:
            if ch in _WS:
                i += 1
                continue
            if ch == "=":
                state = _BEFORE_VALUE
                i += 1
                continue
            if ch == ">":
                if _enter_tag_body(tag_name):
                    state = _RAW
                    raw_name = tag_name.lower()
                    raw_is_js = raw_name == "script"
                else:
                    state = _DATA
                i += 1
                continue
            state = _ATTR_NAME
            attr_name = ch
            i += 1
            continue

        if state == _BEFORE_VALUE:
            if ch in _WS:
                i += 1
                continue
            if ch == '"':
                state = _ATTR_VALUE_DQ
                quote = '"'
                js_quote, js_text, js_in_block_comment, js_in_line_comment = (
                    _prime_js_for_attr(attr_name)
                )
                i += 1
                continue
            if ch == "'":
                state = _ATTR_VALUE_SQ
                quote = "'"
                js_quote, js_text, js_in_block_comment, js_in_line_comment = (
                    _prime_js_for_attr(attr_name)
                )
                i += 1
                continue
            if ch == ">":
                if _enter_tag_body(tag_name):
                    state = _RAW
                    raw_name = tag_name.lower()
                    raw_is_js = raw_name == "script"
                else:
                    state = _DATA
                i += 1
                continue
            state = _ATTR_VALUE_UNQ
            quote = ""
            continue

        if state in (_ATTR_VALUE_DQ, _ATTR_VALUE_SQ, _ATTR_VALUE_UNQ):
            closer = ">" if state == _ATTR_VALUE_UNQ else quote
            attr_l_cur = attr_name.lower() if attr_name else url_scan_attr
            if attr_l_cur != url_scan_attr:
                # A new attribute value: reset the javascript:-prefix probe.
                url_scan_attr = attr_l_cur
                pseudo_probe = ""
                pseudo_state = 0  # 0 = unknown, 1 = confirmed, 2 = rejected
            is_js_attr = attr_l_cur in _JS_HINT_ATTRS
            # A URL attribute whose value starts with ``javascript:`` holds code,
            # not a URL: the browser percent-decodes then evaluates it. The same
            # JS state machine that serves event handlers must run over it, or a
            # value spliced into ``javascript:fetch('/x',{body:'VALUE'})`` is
            # recorded as opaque URL text and every payload built for it is wrong.
            if not is_js_attr and attr_l_cur in _URL_ATTRS:
                if pseudo_state == 0:
                    pseudo_probe += ch
                    if _pseudo_prefix_viable(pseudo_probe):
                        if pseudo_probe.rstrip().lower().startswith(_JS_PSEUDO_PREFIX):
                            pseudo_state = 1
                            # Seed the JS scanner with the prefix it skipped over.
                            js_text.append(pseudo_probe[:-1])
                    else:
                        pseudo_state = 2
                is_js_attr = pseudo_state == 1
            if is_js_attr:
                nxt = html[i + 1] if i + 1 < n else ""
                # The attribute's own delimiter ends the attribute even though the
                # JS sub-state would read it as a string character. Without this,
                # ``onclick="…track('x');"`` never closes — the handler's closing
                # quote is consumed as a JS quote and every later position (a
                # comment body in a ``<p>``, the footer) is classified as still
                # being inside that handler.
                if state != _ATTR_VALUE_UNQ and ch == closer:
                    state = _BEFORE_ATTR
                    attr_name = ""
                    quote = ""
                    js_quote = ""
                    i += 1
                    continue
                if js_in_block_comment:
                    if ch == "*" and nxt == "/":
                        js_in_block_comment = False
                        i += 2
                        continue
                    i += 1
                    continue
                if js_quote:
                    if ch == "\\":
                        push_js(ch)
                        if nxt:
                            push_js(nxt)
                        i += 2
                        continue
                    if ch == js_quote:
                        js_quote = ""
                    push_js(ch)
                    i += 1
                    continue
                if ch in ("'", '"', "`"):
                    js_quote = ch
                    push_js(ch)
                    i += 1
                    continue
                if ch == "/" and nxt == "*":
                    js_in_block_comment = True
                    i += 2
                    continue
                push_js(ch)
            if ch == ">":
                # ">" closes the tag itself, whether it terminated a quoted value
                # or an unquoted one. Returning to _BEFORE_ATTR here made the
                # parser swallow the following element's attributes, so a later
                # canary was attributed to the enclosing <form> instead of its
                # own <input> — which misreported its context as unquoted.
                if _enter_tag_body(tag_name):
                    state = _RAW
                    raw_name = tag_name.lower()
                    raw_is_js = raw_name == "script"
                else:
                    state = _DATA
                attr_name = ""
                quote = ""
                js_quote = ""
                i += 1
                continue
            if ch == closer:
                # The attribute's own quote: the value ends, the tag continues.
                state = _BEFORE_ATTR
                attr_name = ""
                quote = ""
                js_quote = ""
                i += 1
                continue
            if state == _ATTR_VALUE_UNQ and ch in _WS:
                state = _BEFORE_ATTR
                attr_name = ""
                i += 1
                continue
            i += 1
            continue

        # Unknown state — bail out safely
        i += 1

    # ------------------------------------------------------------------
    # Map final state → injection context
    # ------------------------------------------------------------------
    tag_l = tag_name.lower()
    attr_l = attr_name.lower()
    tail = list(js_text)

    if state == _COMMENT:
        return InjectionContext.HTML_COMMENT, tag_l, attr_l, quote, js_quote, tail

    if state == _RAW:
        if raw_name in ("textarea",):
            return InjectionContext.TEXTAREA, tag_l, attr_l, quote, js_quote, tail
        if raw_name == "title":
            return InjectionContext.TITLE, tag_l, attr_l, quote, js_quote, tail
        if raw_name == "style":
            return InjectionContext.CSS_VALUE, tag_l, attr_l, quote, js_quote, tail
        # script → JS context
        return (
            _js_context_from(js_quote, "".join(js_text[-400:])),
            tag_l,
            attr_l,
            quote,
            js_quote,
            tail,
        )

    if state in (_ATTR_VALUE_DQ, _ATTR_VALUE_SQ, _ATTR_VALUE_UNQ):
        if attr_l in _URL_ATTRS:
            # A ``javascript:`` URL is not a URL whose text matters — the browser
            # decodes it and evaluates it as code. A value spliced into
            # ``javascript:fetch('/x', {body:'…VALUE…'})`` therefore sits inside
            # a JS string literal, and only a JS breakout reaches the interpreter.
            # Treating it as a URL attribute produces URL-shaped payloads that the
            # page simply navigates to, never executes.
            if _in_js_pseudo_url(js_text):
                now = _js_context_from(js_quote, "".join(js_text[-400:]))
                # Percent-decoding happens one more time after the attribute is
                # unescaped, so the payload has to travel encoded.
                return now, tag_l, attr_l, quote, js_quote, tail
            return InjectionContext.HTML_ATTR_HREF, tag_l, attr_l, quote, js_quote, tail
        if attr_l in _JS_HINT_ATTRS or (js_quote and attr_l.startswith("on")):
            return InjectionContext.JS_IN_ATTR, tag_l, attr_l, quote, js_quote, tail
        if attr_l == "style":
            return InjectionContext.CSS_VALUE, tag_l, attr_l, quote, js_quote, tail
        if state == _ATTR_VALUE_DQ:
            return InjectionContext.HTML_ATTR_DOUBLE, tag_l, attr_l, quote, js_quote, tail
        if state == _ATTR_VALUE_SQ:
            return InjectionContext.HTML_ATTR_SINGLE, tag_l, attr_l, quote, js_quote, tail
        return InjectionContext.HTML_ATTR_UNQUOTED, tag_l, attr_l, quote, js_quote, tail

    if state in (_TAG_NAME, _BEFORE_ATTR, _ATTR_NAME, _AFTER_ATTR_NAME, _BEFORE_VALUE):
        if encoded_tag:
            return (
                InjectionContext.ENTITY_ENCODED_TAG,
                encoded_tag,
                attr_l,
                quote,
                js_quote,
                tail,
            )
        # Reflection between attributes — can inject a new attribute.
        return InjectionContext.HTML_ATTR_UNQUOTED, tag_l, attr_l, quote, js_quote, tail

    # Data state
    return InjectionContext.HTML_TEXT, tag_l, attr_l, quote, js_quote, tail


def _enter_tag_body(tag_name: str) -> bool:
    """True when closing *tag_name*'s start tag enters a raw-text body."""
    return tag_name.lower() in _RAW_TEXT


_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}


def _regex_allowed(js_so_far: List[str]) -> bool:
    """Decide whether ``/`` opens a regex literal rather than a division."""
    src = "".join(js_so_far).rstrip()
    if not src:
        return True
    last = src[-1]
    if last in _REGEX_PRECEDERS:
        return True
    if last.isalnum() or last in "_$)]":
        # Could still be a keyword like `return`/`typeof`
        m = re.search(r"([A-Za-z_$][\w$]*)$", src)
        if m and m.group(1) in _REGEX_KEYWORDS:
            return True
        return False
    return True


def _prime_js_for_attr(attr_name: str) -> Tuple[str, List[str], bool, bool]:
    """Reset JS tracking state for an event-handler attribute value."""
    if attr_name.lower() in _JS_HINT_ATTRS:
        return "", [], False, False
    return "", [], False, False


def _in_js_pseudo_url(js_text: List[str]) -> bool:
    """Is the value being read inside the code part of a ``javascript:`` URL?

    ``js_text`` is the attribute value emitted so far and ``js_quote`` is the
    string delimiter open at that point. A quote open means the value sits in a
    string literal; a non-zero depth means it sits in code. Both count as code
    execution as long as the attribute really starts with the pseudo-scheme.
    """
    src = "".join(js_text)
    return bool(_JS_PSEUDO_URL_RE.match(src.lstrip(" \t\r\n\r")))


_JS_PSEUDO_URL_RE = re.compile(r"(?i)^\s*javascript\s*:")
# The literal a ``javascript:`` value is built from, plus the whitespace the URL
# parser tolerates in front of it.
_JS_PSEUDO_PREFIX = "javascript:"


def _pseudo_prefix_viable(text: str) -> bool:
    """Could *text* still grow into a ``javascript:`` prefix?

    ``''``, ``'j'``, ``'java'`` and ``'javascript:'`` are viable; ``'ht'`` and
    ``'javascripX'`` are not. A value that stops matching can never become a
    pseudo-URL, so the JS scanner is switched off and the attribute stays an
    ordinary URL attribute.
    """
    t = text.lstrip().lower()
    return _JS_PSEUDO_PREFIX.startswith(t[: len(_JS_PSEUDO_PREFIX)])


def _js_context_from(js_quote: str, js_tail: str) -> InjectionContext:
    if js_quote == '"':
        return InjectionContext.JS_STRING_DOUBLE
    if js_quote == "'":
        return InjectionContext.JS_STRING_SINGLE
    if js_quote == "`":
        return InjectionContext.JS_TEMPLATE
    return InjectionContext.JS_CODE
