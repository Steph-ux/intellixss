"""Character survival probe analysis (pure)."""

from __future__ import annotations

import html
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote

from intellixss.models import CharProbeResult

PROBE_CHARS = list("<>\"'`{}[]/\\=();:+-|!")


def build_probe_string(uid: str) -> str:
    """Build a unique probe sandwich for one HTTP request."""
    return f"xssP{uid}" + "".join(PROBE_CHARS) + f"P{uid}xss"


def parse_probe_response(response: str, uid: str) -> Tuple[bool, str]:
    """Extract the reflected region between markers. Returns (found, region)."""
    start_m = f"xssP{uid}"
    end_m = f"P{uid}xss"
    # raw
    m = re.search(re.escape(start_m) + r"([\s\S]*?)" + re.escape(end_m), response)
    if m:
        return True, m.group(1)
    # HTML-encoded markers
    start_e = html.escape(start_m)
    end_e = html.escape(end_m)
    m = re.search(re.escape(start_e) + r"([\s\S]*?)" + re.escape(end_e), response)
    if m:
        return True, html.unescape(m.group(1))
    return False, ""


def reflect_offset(
    canary_body: str, probe_body: str, canary: str, probe: str, canary_pos: int
) -> Optional[int]:
    """Map an injection point in the canary response onto the probe response.

    The two requests differ only in the injected value, so the document around
    the two reflections is structurally identical. Counting reflections from
    the start identifies which probe echo corresponds to the canary echo we
    chose to attack — rather than assuming it is the first one.

    Returns ``None`` when the reflection counts disagree, which means the value
    itself changed the parse tree (parsed-in-markup) and no safe mapping exists.
    """
    canary_hits = [m.start() for m in re.finditer(re.escape(canary), canary_body)]
    if canary_pos not in canary_hits:
        return None
    probe_hits = [m.start() for m in re.finditer(re.escape(probe), probe_body)]
    if len(probe_hits) != len(canary_hits):
        return None
    return probe_hits[canary_hits.index(canary_pos)]


def analyze_char_probe_at(
    param: str, uid: str, response: str, anchor: int
) -> CharProbeResult:
    """Measure survival at one specific reflection, not the first one found.

    A parameter echoed twice — say once in a heading and once inside an
    attribute — is filtered differently at each point. ``analyze_char_probe``
    reads the first echo and therefore reports the heading's escaping for an
    injection point that lives in the attribute. ``anchor`` is the offset of
    the reflection we actually intend to attack; only the probe sandwich
    covering that offset is measured.

    Falls back to the whole-response measurement when no sandwich spans the
    anchor, so a mangled probe still yields a usable answer.
    """
    start_m = f"xssP{uid}"
    end_m = f"P{uid}xss"
    spans: List[Tuple[int, int]] = []
    for pattern in (re.escape(start_m) + r"([\s\S]*?)" + re.escape(end_m),):
        spans.extend((m.start(1), m.end(1)) for m in re.finditer(pattern, response))
    # HTML-encoded markers, offsets shifted back onto the raw response.
    for m in re.finditer(
        re.escape(html.escape(start_m)) + r"([\s\S]*?)" + re.escape(html.escape(end_m)),
        response,
    ):
        spans.append((m.start(1), m.end(1)))
    if not spans:
        return analyze_char_probe(param, uid, response)

    def distance(span: Tuple[int, int]) -> int:
        lo, hi = span
        if lo <= anchor <= hi:
            return 0
        return min(abs(anchor - lo), abs(anchor - hi))

    lo, hi = min(spans, key=distance)
    if not (lo <= anchor <= hi):
        return analyze_char_probe(param, uid, response)
    region = html.unescape(response[lo:hi])
    return _classify(param, region, response)


def analyze_char_probe(param: str, uid: str, response: str) -> CharProbeResult:
    """Classify which XSS-relevant characters survived, were encoded, or blocked."""
    found, region = parse_probe_response(response, uid)
    if found:
        return _classify(param, region, response)
    # The sandwich may have been mangled but the parameter still echoed: look
    # for the unique uid on its own. Apps that "sanitise" by dropping a whole
    # tail keep the uid in place while the characters after it disappear.
    if uid in response:
        idx = response.find(uid)
        region = response[idx : idx + 200]
        result = _classify(param, region, response)
        # A pattern like ``&#39;)`` (entity, close-paren, rest all missing) is a
        # stop-leak on the quote: the probe was truncated right after it. Mark
        # the quote as encoded so the generator sends the decoded form.
        if "'" in result.encoded_chars and "'" not in result.allowed_chars:
            for ch in "'()":
                if ch not in result.encoded_chars:
                    result.encoded_chars[ch] = html.escape(ch)
        return result

    # maybe whole probe escaped as one blob
    probe = build_probe_string(uid)
    if html.escape(probe) in response:
        return CharProbeResult(
            param=param,
            reflected=True,
            allowed_chars=set(),
            blocked_chars=set(PROBE_CHARS),
            encoded_chars={c: html.escape(c) for c in PROBE_CHARS if c in "<>\"'"},
            raw_reflection=html.escape(probe)[:80],
        )
    return CharProbeResult(
        param=param,
        reflected=False,
        allowed_chars=set(),
        blocked_chars=set(PROBE_CHARS),
        encoded_chars={},
        raw_reflection="",
    )


def _classify(param: str, region: str, response: str) -> CharProbeResult:
    allowed: Set[str] = set()
    blocked: Set[str] = set()
    encoded: Dict[str, str] = {}

    # Decode common entity forms in region for comparison
    region_unesc = html.unescape(region)
    region_unesc = unquote(region_unesc)

    for ch in PROBE_CHARS:
        if ch in region:
            allowed.add(ch)
        elif html.escape(ch) in region or _entity_forms(ch, region):
            encoded[ch] = _entity_forms(ch, region) or html.escape(ch)
        elif ch in region_unesc:
            # The character is present once entities/percent-encoding are
            # decoded, so the app re-encodes it rather than rejecting it.
            encoded[ch] = html.escape(ch)
        else:
            blocked.add(ch)

    return CharProbeResult(
        param=param,
        reflected=True,
        allowed_chars=allowed,
        blocked_chars=blocked,
        encoded_chars=encoded,
        raw_reflection=region[:120],
    )


def _entity_forms(ch: str, region: str) -> str:
    mapping = {
        "<": ["&lt;", "&#60;", "&#x3c;"],
        ">": ["&gt;", "&#62;", "&#x3e;"],
        '"': ["&quot;", "&#34;", "&#x22;"],
        "'": ["&#39;", "&#x27;", "&apos;"],
        "&": ["&amp;"],
    }
    for form in mapping.get(ch, []):
        if form in region.lower() or form in region:
            return form
    # Any numeric form of the codepoint counts (&#40;, &#x00028;, …).
    cp = ord(ch)
    m = re.search(rf"&#(?:x0*{cp:x}|0*{cp});", region, re.I)
    if m:
        return m.group(0)
    return ""


def single_char_probe(uid: str, ch: str) -> str:
    """Probe one metacharacter between two alphanumeric sentinels.

    The stacked probe sends every metacharacter at once, which is
    self-defeating: if ``"`` survives it closes the attribute it was injected
    into and the reflected region can no longer be located, so a character that
    actually went through is recorded as missing. Encasing a single character
    in plain alphanumerics keeps the sentinels findable whatever the character
    does to the surrounding markup.
    """
    return f"S{uid}A{ch}Z{uid}E"


def measure_single_char(
    param: str, uid: str, ch: str, response: str, anchor: Optional[int] = None
) -> str:
    """Classify one character as ``allowed``, ``encoded``, ``escaped``, ``blocked`` or ``absent``.

    ``escaped`` is separate from ``blocked`` on purpose. An app that prefixes
    the character with a backslash has not removed it: the character reached
    the page and an HTML entity for it would arrive after the escaper ran, so
    ``&#39;`` still produces a real quote. Reporting that as "blocked" told the
    generator to give up on a delimiter it could actually deliver.

    ``anchor`` restricts the match to the reflection at that offset, so two
    echoes of the same parameter (a heading and an attribute) are judged
    separately instead of the first one deciding for both.
    """
    start_s = f"S{uid}A"
    end_s = f"Z{uid}E"
    for m in re.finditer(re.escape(start_s) + r"([\s\S]*?)" + re.escape(end_s), response):
        if anchor is not None and not (m.start() <= anchor <= m.end()):
            continue
        inner = m.group(1)
        if inner == ch:
            return "allowed"
        if f"\\{ch}" in inner:
            # Present, merely prefixed by a backslash: the character reached
            # the page, so an entity form of it still produces a real one.
            return "escaped"
        decoded = html.unescape(html.unescape(unquote(inner)))
        if ch in decoded:
            return "encoded"
        return "blocked"
    return "absent"

