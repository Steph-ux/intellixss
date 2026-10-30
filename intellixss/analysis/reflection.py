"""Reflection and effectiveness helpers (pure, network-free)."""

from __future__ import annotations

import html
import re
from typing import List, Optional, Tuple
from urllib.parse import unquote


def find_reflection(response: str, needle: str, window: int = 80) -> Optional[str]:
    """Return a snippet around the first reflection of *needle* (raw or decoded forms)."""
    if not response or not needle:
        return None

    candidates = _needle_variants(needle)
    for cand in candidates:
        idx = response.find(cand)
        if idx == -1:
            idx = response.lower().find(cand.lower())
            if idx == -1:
                continue
        start = max(0, idx - window)
        end = min(len(response), idx + len(cand) + window)
        return response[start:end]
    return None


def _needle_variants(needle: str) -> List[str]:
    variants = [needle]
    try:
        d1 = unquote(needle)
        if d1 != needle:
            variants.append(d1)
    except Exception:
        pass
    variants.append(html.escape(needle))
    if len(needle) > 12:
        variants.append(needle[:12])
    return list(dict.fromkeys(variants))


def escapes_in_place(response: str, payload: str) -> bool:
    """True when *payload* appears in *response* with backslashes inserted.

    Quote-escaping apps rewrite the value they were given: they do not touch
    the rest of it, they prefix each ``'`` or ``"`` with a backslash. So the
    payload is present, character for character, once the *added* backslashes
    are removed. Testing that is what distinguishes "the app echoed my value
    and escaped its quotes" from "the app mangled my value", which the plain
    substring test cannot tell apart.
    """
    if not response or not payload or len(payload) < 8:
        return False
    if "\\" not in response:
        return False
    squashed = re.sub(r"\\(?=['\"\\])", "", response)
    if payload in squashed:
        return True
    # A JavaScript-aware escaper may write a quote as ``\u0027`` rather than
    # ``\'``. The bytes differ, but the value the interpreter sees is the same
    # character, so a payload that came back this way is faithfully reflected
    # and still executes — judging it as "mangled" is what made a template
    # literal lab read as no reflection at all.
    return payload in re.sub(r"\\u([0-9a-fA-F]{4})", _unicode_escape_char, response)


def _unicode_escape_char(m: "re.Match") -> str:
    """``\\u0027`` → ``'``, keeping anything that is not a valid code point."""
    try:
        return chr(int(m.group(1), 16))
    except (ValueError, OverflowError):
        return m.group(0)


def reflection_score(response: str, payload: str) -> float:
    """
    0.0 = not reflected, 1.0 = raw payload reflected unchanged.
    Intermediate scores for encoded / partial survival.
    """
    if not response or not payload:
        return 0.0
    if payload in response:
        return 1.0
    # The app may escape in place: each quote becomes ``\'`` and the rest of the
    # payload is untouched. That is a *faithful* reflection of a value the
    # escaper rewrote, not a partial one, so it scores as full — the escaping is
    # then judged by the technique's own syntax check, not by this score.
    if escapes_in_place(response, payload):
        return 1.0
    if html.escape(payload) in response:
        return 0.35
    stripped = payload.replace("<", "").replace(">", "")
    if stripped and stripped in response:
        return 0.45
    tokens = re.findall(r"[a-zA-Z_]{4,}", payload)
    hits = sum(1 for t in tokens if t in response)
    if tokens and hits == len(tokens):
        return 0.55
    if tokens and hits:
        return 0.25
    for part in (payload[:8], payload[-8:]):
        if len(part) >= 4 and part in response:
            return 0.2
    return 0.0


def is_payload_effective(
    response: str, payload: str, context_hint: str = "html_text"
) -> Tuple[bool, str]:
    """
    Decide whether the response still contains an *executable* form of the payload.

    Merely reflecting the text ``alert(1)`` (or ``'-alert(1)-'``) inside HTML text
    or a passive attribute value is NOT XSS. We require structural evidence:
    raw tags/handlers, JS string breakouts in event attrs, or javascript: hrefs.

    Ambient page content (logo ``<img>``, generic ``onerror=fallback``) must never
    satisfy confirmation for an unrelated payload.
    """
    if not response or not payload:
        return False, "empty"

    decoded = html.unescape(response)
    score = reflection_score(response, payload)
    score_dec = reflection_score(decoded, payload)
    ctx = (context_hint or "html_text").lower()

    # --- href context: only navigable script URLs ---
    if ctx == "html_attr_href":
        if "javascript:" in payload.lower() and re.search(
            r"javascript\s*:\s*(?:alert|prompt|confirm)", decoded, re.I
        ):
            # require distinctive javascript:alert-style reflection, not bare protocol
            if _distinctive_reflection(payload, decoded) or _distinctive_reflection(
                payload, response
            ):
                return True, "javascript_href"
            # full payload present
            if payload in decoded or payload in response:
                return True, "javascript_href"
        if payload.lower().startswith("data:text/html") and "data:text/html" in decoded.lower():
            if payload in decoded or payload[:20] in decoded:
                return True, "data_href"
        return False, "href_not_javascript"

    # --- JS inside attribute (onload="startTimer('…')") ---
    if ctx in ("js_in_attr",) or ctx.startswith("js_in"):
        # Judge only the handler value the payload landed in. Decoding the
        # *whole* response would "heal" entities the app added at encode time:
        # ``startTimer('1&quot;&gt;…')`` is inert in a browser, yet unescaping
        # the page turns it into a tag that was never emitted.
        zones = _handler_zones(response, payload)
        for zone in zones:
            # Pass the raw slice: the helper decodes internally but still sees
            # which brackets the app encoded, so it cannot be fooled by entities
            # the browser would leave as literal text.
            for probe in (html.unescape(payload), payload):
                if _js_syntax_executable(probe, zone):
                    return True, (
                        "js_in_attr_breakout"
                        if probe == payload
                        else "js_in_attr_breakout_after_entity_decode"
                    )
        if zones:
            return False, "js_in_attr_no_breakout"
        # No handler zone could be located (payload landed elsewhere in the
        # page): fall back to the whole-response heuristic.
        for probe in (html.unescape(payload), payload):
            if _js_breakout_executable(probe, decoded):
                return True, (
                    "js_in_attr_breakout"
                    if probe == payload
                    else "js_in_attr_breakout_after_entity_decode"
                )
        return False, "js_in_attr_no_breakout"

    # --- Quoted HTML attributes: MUST break out of the attribute first ---
    if ctx in ("html_attr_double", "html_attr_single"):
        if _attr_breakout_executable(payload, response, decoded, ctx):
            return True, "attr_breakout_executable"
        return False, "attr_not_executable"

    # --- Unquoted attributes: need event handler or tag injection from payload ---
    if ctx == "html_attr_unquoted":
        if _event_handler_executable(payload, response) or _event_handler_executable(
            payload, decoded
        ):
            return True, "unquoted_event_handler"
        if _html_tag_executable(payload, response) or _html_tag_executable(payload, decoded):
            return True, "unquoted_tag_injection"
        return False, "unquoted_not_executable"

    # --- HTML text / unknown / script contexts ---
    # Judged on the *raw* response only. Unescaping the whole document turns
    # ``&lt;img src=x onerror=…&gt;`` into a tag that the server never emitted
    # and the browser never parses, so an app that escapes correctly would be
    # reported vulnerable. Entity-encoded payloads that really do execute are
    # handled by the JSON/JS-attribute paths above, where the browser decodes
    # the value before interpreting it.
    if score >= 1.0:
        if _html_tag_executable(payload, response):
            return True, "raw_executable_reflection"
        if _event_handler_executable(payload, response):
            return True, "raw_event_handler"
        if ctx in ("js_code", "js_string_double", "js_string_single", "js_template"):
            if _js_string_breakout_executable(payload, response, ctx):
                return True, "js_string_breakout"
        return False, "raw_benign_reflection"

    # Partial scores: ambient token matches only — require distinctive markers.
    # Raw response only, for the same reason as the block above: an entity the
    # server emitted is text, and unescaping the document manufactures markup.
    if score >= 0.5:
        if _distinctive_reflection(payload, response):
            if _html_tag_executable(payload, response):
                return True, "partial_executable_reflection"
            if _event_handler_executable(payload, response):
                return True, "partial_event_handler"

    return False, f"not_effective:score={score:.2f}/dec={score_dec:.2f}"

# ---------------------------------------------------------------------------
# Distinctive reflection (anti ambient-HTML false positives)
# ---------------------------------------------------------------------------

# Generic openers that appear constantly in real pages — never use alone as proof.
_AMBIENT_PREFIXES = frozenset(
    {
        " onerr",
        " onload",
        " onfoc",
        " oncli",
        "<img s",
        "<img/",
        "<img ",
        "<div ",
        "<span",
        "<a hr",
        "src=\"",
        "src='",
        "src=",
    }
)


def _distinctive_markers(payload: str) -> List[str]:
    """
    High-specificity substrings that prove *this* payload survived — not ambient HTML.

    Prefer bindings like ``onerror=alert`` / ``src=x onerror`` / full strip over
    generic `` onerr`` or ``<img src``.
    """
    if not payload:
        return []
    markers: List[str] = []
    stripped = payload.strip()
    if len(stripped) >= 10:
        markers.append(stripped)

    # handler bound to alert/prompt/confirm — rare in ambient pages as a unit
    for m in re.finditer(
        r"on[a-z]{3,15}\s*=\s*(?:alert|prompt|confirm)(?:\s*\(|\s*`)",
        payload,
        re.I,
    ):
        markers.append(m.group(0))
    for m in re.finditer(
        r"on[a-z]{3,15}\s*=\s*(?:alert|prompt|confirm)",
        payload,
        re.I,
    ):
        markers.append(m.group(0))

    # XSS classic: src=x onerror=…
    for m in re.finditer(r"src\s*=\s*x\s+onerror\s*=", payload, re.I):
        markers.append(m.group(0))

    # tag/handler compound openers unique enough: <svg/onload=alert
    for m in re.finditer(
        r"<[a-zA-Z][\w/:-]{0,12}(?:\s|/)on[a-z]+\s*=\s*(?:alert|prompt|confirm)?",
        payload,
        re.I,
    ):
        s = m.group(0)
        if len(s) >= 10:
            markers.append(s)

    # javascript:alert
    for m in re.finditer(r"javascript\s*:\s*(?:alert|prompt|confirm)", payload, re.I):
        markers.append(m.group(0))

    # JS breakout markers
    for m in re.finditer(
        r"""['"]\s*\)\s*;\s*(?:alert|prompt|confirm)|['"]\s*;\s*(?:alert|prompt|confirm)""",
        payload,
        re.I,
    ):
        markers.append(m.group(0))

    # Deduplicate, drop ambient-only prefixes
    out: List[str] = []
    seen = set()
    for mk in markers:
        key = mk.lower()
        if key in seen:
            continue
        if mk[:6].lower() in _AMBIENT_PREFIXES or mk[:7].lower() in _AMBIENT_PREFIXES:
            # keep only if longer distinctive remainder
            if len(mk) < 12:
                continue
        seen.add(key)
        out.append(mk)
    return out


def _distinctive_reflection(payload: str, response: str) -> bool:
    """True if a distinctive payload marker appears raw (or case-folded) in response."""
    if not payload or not response:
        return False
    if payload in response or payload.strip() in response:
        return True
    for mk in _distinctive_markers(payload):
        if mk in response:
            return True
        # mixed-case WAF-style payloads
        if len(mk) >= 10 and re.search(re.escape(mk), response, re.I):
            return True
    return False


def _payload_fragment_present(payload: str, response: str, min_len: int = 8) -> bool:
    """
    Back-compat name used by callers/tests. Only distinctive markers count —
    never ambient 6-char prefixes like `` onerr`` or ``<img sr``.
    """
    return _distinctive_reflection(payload, response)


# ---------------------------------------------------------------------------
# Structural executability checks
# ---------------------------------------------------------------------------

_TAG_EXEC = re.compile(
    r"<(?:script|svg|img|details|body|xss|custom|iframe|video|audio|math|input|select|textarea|marquee|object|embed)\b",
    re.I,
)
_EVENT_EXEC = re.compile(
    r"""\bon(?:error|load|focus|mouseover|pointerover|click|toggle|pageshow|animationend|start|end)\s*=""",
    re.I,
)
_JS_BREAKOUT = re.compile(
    r"""['"]\s*\)\s*;\s*(?:alert|prompt|confirm)\s*(?:\(|`)|"""
    r"""['"]\s*;\s*(?:alert|prompt|confirm)\s*(?:\(|`)|"""
    r"""\)\s*;\s*(?:alert|prompt|confirm)\s*(?:\(|`)""",
    re.I,
)
# A quote behind a backslash closes a JS string once the app has added its own
# escape to that backslash: the app reaches that state by prefixing the escape
# to a value that already ends in one.
_BS_TEXT = re.compile(r"\\['\"]")
# A statement that reaches the network carries the proof of execution itself:
# the request to the marker host is observable, and it needs no ``alert``.
_EXFIL_STMT = re.compile(r"""\.src\s*=\s*[`'"]|\bimport\s*\(""", re.I)


def _html_tag_executable(
    payload: str, response: str, decoded: str = ""
) -> bool:
    """
    True only when the payload's own tag/handler structure is reflected.

    Full payload reflection with a tag is enough. Partial confirmation requires
    a *distinctive* marker (e.g. ``src=x onerror=`` or ``<svg/onload=alert``),
    never ambient ``<img src=…>`` alone.
    """
    if not payload or not response:
        return False
    if not re.search(r"<\w", payload):
        return False

    # Entity-decoded server output executes in browsers (&#60;img&#62; → <img>)
    if decoded and payload in decoded:
        return True
    if payload in response:
        if html.escape(payload) in response and payload not in response:
            return False
        return bool(_TAG_EXEC.search(payload) or re.search(r"<\w", payload))

    if not _distinctive_reflection(payload, response):
        return False

    # Distinctive marker present: also require the payload's tag family raw.
    # The name alone proves nothing — a page carries its own ``<img>`` logo —
    # so the opener has to sit right before the distinctive marker, inside the
    # same tag, which is what the escaped echo fails to satisfy.
    tag_names = re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", payload)
    if not tag_names:
        return False
    marker = re.search(
        r"\bon[a-z]{3,15}\s*=\s*(?:alert|prompt|confirm)", payload, re.I
    )
    anchor = marker.group(0) if marker else payload
    pos = response.lower().find(anchor.lower())
    if pos < 0:
        return False
    lead = response[max(0, pos - 300):pos].lower()
    if lead.rfind("&lt;") > lead.rfind("<"):
        return False
    for name in tag_names:
        if re.search(rf"<{re.escape(name)}\b", lead):
            return True
    return False


def _event_handler_executable(payload: str, response: str) -> bool:
    """
    Payload event handler still present as a *payload-specific* binding.

    Ambient ``onerror=fallback`` / ``onload=init`` must NOT confirm
    `` onerror=alert(1) ``. The binding also has to sit inside a real opening
    tag: an escaped echo (``&lt;img src=x onerror=alert(1)&gt;``) contains the
    same text but never becomes an element, so the string match alone would
    report a vulnerability the browser cannot reach.
    """
    if not re.search(r"\bon[a-z]+\s*=", payload, re.I):
        return False

    if not _inside_open_tag(response, payload):
        return False

    # Full payload present
    if payload in response or payload.strip() in response:
        return True

    # Distinctive: onX=alert/prompt/confirm from payload must appear as a unit
    for m in re.finditer(
        r"(on[a-z]{3,15})\s*=\s*(alert|prompt|confirm)",
        payload,
        re.I,
    ):
        pat = rf"{m.group(1)}\s*=\s*{m.group(2)}"
        if re.search(pat, response, re.I):
            return True

    # autofocus onfocus=alert style
    if re.search(r"autofocus\s+onfocus\s*=\s*alert", payload, re.I) and re.search(
        r"autofocus\s+onfocus\s*=\s*alert", response, re.I
    ):
        return True

    return False


def _inside_open_tag(response: str, payload: str) -> bool:
    """True when the payload's handler appears inside a tag the parser opens.

    The anchor is the *handler*, not the whole payload: an app that escapes the
    quotes still leaves ``onerror=alert`` readable in the text, and matching the
    payload verbatim would then silently skip the check. A ``<`` introduced by
    ``&lt;`` is text, so the nearest raw ``<`` must be a genuine tag opener.
    """
    m = re.search(r"\bon[a-z]{3,15}\s*=", payload, re.I)
    anchor = m.group(0) if m else payload
    start = response.lower().find(anchor.lower())
    if start < 0:
        return False
    window = response[max(0, start - 400):start].lower()
    last_lt = window.rfind("<")
    if last_lt < 0:
        return False
    # If an escaped opener ("&lt;") sits between that "<" and the handler, the
    # handler belongs inside text, not inside the earlier real tag.
    if window.rfind("&lt;") > last_lt:
        return False
    nxt = window[last_lt + 1:last_lt + 2]
    return bool(nxt) and (nxt.isalpha() or nxt in ("/", "!"))


def _handler_zones(response: str, payload: str, window: int = 400) -> List[str]:
    """Return the ``on*`` handler values the payload was reflected into.

    Entity-decoding a whole page lets an encoded payload look executable when
    the browser would only ever see inert text, so the JS-in-attribute oracle
    needs the exact slices that a browser would hand to the JS engine.
    """
    zones: List[str] = []
    for m in re.finditer(r"\bon[a-z]{3,15}\s*=\s*", response, re.I):
        quote = response[m.end() : m.end() + 1]
        if quote in ('"', "'"):
            close = response.find(quote, m.end() + 1)
            zone = response[m.end() + 1 : close if close != -1 else m.end() + window]
        else:
            zone = response[m.end() : m.end() + window]
        zones.append(zone)
        # Also offer the whole *tag* the handler belongs to. A payload that
        # closes the attribute is only visible once the tag is read as markup;
        # decoding this tag is exactly what the browser does, and it cannot
        # reach any other element on the page.
        start = response.rfind("<", 0, m.start())
        if start != -1:
            end = response.find(">", m.end())
            if end != -1:
                zones.append(response[start : end + 1])
    # The reflection may sit inside an inline <script> (js_code hint given a
    # handler context); include those bodies too so the fallback is not blind.
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", response, re.I | re.S):
        zones.append(m.group(1))
    return zones


def _stripped_head(payload: str) -> str:
    """Leading fragment of *payload* up to its first angle bracket.

    A breakout that closes an attribute keeps ``1'><img`` intact while the
    rest is re-parsed as a new element, so the full payload never appears as a
    contiguous string — the head is what proves the escape happened.
    """
    m = re.search(r"<[a-zA-Z/!]", payload)
    return payload[: m.start()] if m else ""


def _stripped_head(payload: str) -> str:
    """Leading fragment of *payload* through the attribute-closing ``>``.

    A breakout that closes an attribute keeps ``1'><img`` intact while the rest
    is re-parsed as a new element, so the full payload never appears as a
    contiguous string. The head through the first ``>`` is the shortest prefix
    specific enough to prove that escape actually happened.
    """
    m = re.search(r"<[a-zA-Z/!]", payload)
    if not m:
        return ""
    gt = payload.find(">", m.start())
    return payload[: gt + 1] if gt != -1 else payload[: m.start() + 1]


def _js_syntax_executable(payload: str, zone: str) -> bool:
    """True when *payload* still forms runnable JS inside a live handler.

    Structured payloads — ``('1',alert(m),'')`` style comma expressions and
    ``a||alert(m)||b`` — stay valid whatever the page appended after them, so
    they are accepted on their own shape.

    A bare ``');alert(m)//`` breakout is different: the handler parser reads
    the whole attribute value, and ``startTimer('1');alert(m)');`` is a syntax
    error that never runs a line. Accept it only when the reflected tail after
    the payload closes what the payload opened, which we can read off *zone*.
    """
    if not re.search(r"(?:alert|prompt|confirm)\s*(?:\(|`)", payload, re.I):
        return False

    has_comma_form = bool(
        re.search(r"""["']\s*,\s*(?:alert|prompt|confirm)\s*(?:\(|`)""", payload, re.I)
    )
    if has_comma_form or re.search(r"(?:\|\||&&)\s*(?:alert|prompt|confirm)", payload, re.I):
        return True

    if "<" in payload:
        return _js_breakout_executable(payload, zone)

    if not re.search(r"""["']\s*\)""", payload):
        return False

    # Where does the payload sit inside the zone, and what follows it?
    idx = zone.find(html.unescape(payload))
    tail = ""
    if idx != -1:
        tail = html.unescape(zone)[idx + len(payload) :]
    else:
        marker = _extract_marker_like(payload)
        if marker and marker in zone:
            tail = zone.split(marker, 1)[1]
    # ``//`` or ``<!--`` in the payload comments out the tail.
    if "//" in payload or "<!--" in payload:
        return not re.search(r"(?:alert|prompt|confirm)", tail, re.I) and tail.strip() != ""
    # Otherwise the tail must supply exactly the closing syntax we need.
    opens = payload.count("(") - payload.count(")")
    closes = tail.count(")") - tail.count("(")
    return opens <= 0 or closes >= opens


def _extract_marker_like(payload: str) -> str:
    m = re.search(r"ixm[0-9a-f]{6,}", payload)
    return m.group(0) if m else ""


def _js_breakout_executable(payload: str, decoded_response: str) -> bool:
    """
    True when payload is a JS string breakout that survives into decoded HTML/JS.
    Example L4: startTimer('3');alert(1);//');  after entity decode.
    """
    # Keep the raw slice: the checks below inspect both the encoded and the
    # browser-decoded view, and the encoded view is what tells us whether the
    # app itself neutralised the angle brackets.
    raw = decoded_response
    decoded_response = html.unescape(raw)
    encoded_brackets = bool(re.search(r"&lt;[a-zA-Z/]", raw))
    if not re.search(r"(?:alert|prompt|confirm)\s*(?:\(|`)", payload, re.I):
        return False
    # ``1'||alert(1)||'`` completes the enclosing expression without a closing
    # parenthesis: it stays valid whatever literal the page wrapped it in, so
    # it is the technique of choice where the server truncates at ``)``.
    if re.search(
        r"""(?:\|\||&&)\s*(?:alert|prompt|confirm)\s*(?:\(|`)""", payload, re.I
    ):
        return True
    head = _stripped_head(payload)
    # Attribute closed and a new element opened: the reflected head followed by
    # a real tag whose handler fires.
    if head and head in decoded_response:
        tag_names = re.findall(r"<([a-zA-Z][a-zA-Z0-9]*)", payload)
        for name in tag_names:
            if re.search(rf"<{re.escape(name)}\b[^>]*\bon[a-z]+\s*=\s*", decoded_response, re.I):
                return True
        # No new element fired. Angle brackets that are still entity-encoded
        # were emitted by the app, so the browser shows text, not markup.
        if encoded_brackets:
            return False

    if payload in decoded_response:
        if re.search(
            r"""['"]\s*\)\s*;|(?:^|[^a-z])\);\s*(?:alert|prompt|confirm)|['"]\s*;\s*(?:alert|prompt|confirm)""",
            payload,
            re.I,
        ):
            return True
        if re.search(r"""['"]\s*\)\s*;\s*(?:alert|prompt|confirm)""", decoded_response, re.I):
            return True
    if _JS_BREAKOUT.search(decoded_response) and re.search(
        r"(?:alert|prompt|confirm)\s*(?:\(|`)", payload, re.I
    ):
        if any(tok in payload for tok in ("');", '");', "';", '";', "//")):
            # require distinctive breakout snippet also in decoded body
            for mk in _distinctive_markers(payload):
                if mk in decoded_response or (
                    len(mk) >= 8 and re.search(re.escape(mk), decoded_response, re.I)
                ):
                    return True
            if payload in decoded_response:
                return True
    return False


def _js_string_breakout_executable(payload: str, decoded: str, ctx: str) -> bool:
    if (
        payload not in decoded
        and not _distinctive_reflection(payload, decoded)
        and not escapes_in_place(decoded, payload)
    ):
        return False
    if ctx in ("js_string_double", "js_string_single", "js_template"):
        if ctx == "js_template":
            # A template literal is not escaped by closing it: ``${…}`` is
            # evaluated in place, inside the literal, with the surrounding
            # quotes intact. Requiring a string breakout here would reject the
            # one payload that works, so the interpolation itself is judged —
            # and it must call something, not merely interpolate a value.
            if re.search(r"\$\{[^}]*\b(?:alert|prompt|confirm|eval|fetch)\b", payload, re.I):
                return True
            if _EXFIL_STMT.search(payload):
                return True
        if re.search(r"""['"`]\s*;\s*(?:alert|prompt|confirm)|</script>""", payload, re.I):
            return True
        # A statement that fetches a marker host is an execution primitive: the
        # request is the proof, and it needs neither ``alert`` nor a backtick.
        if _EXFIL_STMT.search(payload):
            return True
        # A run of backslashes before the quote is the breakout: whatever the
        # app escaped, an even run reads as a literal backslash and the quote
        # then really closes the string.
        return bool(_BS_TEXT.search(payload))
    if ctx == "js_code":
        return bool(re.search(r"(?:alert|prompt|confirm)\s*(?:\(|`)", payload, re.I))
    return False


def _attr_breakout_executable(
    payload: str, response: str, decoded: str, ctx: str
) -> bool:
    """Quote breakout into event handler or new tag — requires distinctive reflection."""
    body = decoded if payload in decoded or _distinctive_reflection(payload, decoded) else response
    if payload not in body and not _distinctive_reflection(payload, body):
        if payload not in response and not _distinctive_reflection(payload, response):
            return False
        body = response

    # Event-handler breakout reflected as distinctive unit
    if re.search(r"""["']\s*on[a-z]+\s*=""", payload, re.I):
        for m in re.finditer(
            r"""(["'])\s*(on[a-z]+)\s*=\s*(?:(["']?)(alert|prompt|confirm)|)""",
            payload,
            re.I,
        ):
            # at least quote+handler in body
            if re.search(
                rf"""{re.escape(m.group(1))}\s*{m.group(2)}\s*=""", body, re.I
            ) and _distinctive_reflection(payload, body):
                # prefer alert binding when payload has it
                if re.search(r"(?:alert|prompt|confirm)", payload, re.I):
                    if re.search(
                        rf"{m.group(2)}\s*=\s*(?:alert|prompt|confirm)", body, re.I
                    ):
                        return True
                else:
                    return True
        # " onmouseover="alert(1) full payload
        if payload in body or payload.strip() in body:
            return True

    # Tag injection after closing quote: "><img ...
    if re.search(r"""["']\s*>""", payload) and (
        payload in body or _distinctive_reflection(payload, body)
    ):
        if '"><' in body or "'><" in body or re.search(r"""["']\s*>\s*<""", body):
            return True

    if re.search(r"""["']\s*(?:autofocus\s+)?on[a-z]+""", payload, re.I) and (
        payload in body or _distinctive_reflection(payload, body)
    ):
        if re.search(r"""\bon[a-z]+\s*=\s*(?:alert|prompt|confirm)""", body, re.I):
            return True

    return False


def _looks_executable(payload: str, response: str) -> bool:
    """
    Backward-compatible helper used by tests/callers without context.
    Strict: tags or event handlers only — never bare alert() text.
    """
    return _html_tag_executable(payload, response) or _event_handler_executable(
        payload, response
    )
