"""Payload-quote selection: HTML attribute delimiter vs JS string delimiter.

Level 4 of xss-game is the canonical case: the sink is
``<img onload="startTimer('PAYLOAD');">``. The HTML attribute is double
quoted, but the string a payload can break out of is single quoted. Using the
attribute quote produces payloads that are inert on every handler like it.
"""

from intellixss.analysis.context import ContextHit
from intellixss.models import InjectionContext


def test_js_string_quote_wins_over_attribute_quote():
    hit = ContextHit(
        context=InjectionContext.JS_IN_ATTR,
        quote_char='"',
        js_string_quote="'",
    )
    assert hit.payload_quote == "'"


def test_js_string_double_quoted_handler():
    hit = ContextHit(
        context=InjectionContext.JS_IN_ATTR,
        quote_char="'",
        js_string_quote='"',
    )
    assert hit.payload_quote == '"'


def test_attribute_context_uses_attribute_quote():
    hit = ContextHit(context=InjectionContext.HTML_ATTR_DOUBLE, quote_char='"')
    assert hit.payload_quote == '"'


def test_missing_js_quote_falls_back_to_attribute_quote():
    hit = ContextHit(context=InjectionContext.JS_IN_ATTR, quote_char='"')
    assert hit.payload_quote == '"'


def test_script_body_context_uses_js_quote():
    hit = ContextHit(
        context=InjectionContext.JS_STRING_SINGLE, js_string_quote="'"
    )
    assert hit.payload_quote == "'"


def test_level4_comma_payload_uses_js_quote_and_ranks_first():
    """The payload that actually fires on level 4 must be generated with a
    single quote and survive the character filter (the server entity-encodes
    quotes, which must not be treated as a dead character)."""
    from intellixss.models import CharProbeResult
    from intellixss.payloads.generator import generate_payloads

    probe = CharProbeResult(
        param="timer",
        reflected=True,
        encoded_chars={"'": "&#39;", '"': "&quot;", "<": "&lt;", ">": "&gt;"},
    )
    payloads = generate_payloads(
        InjectionContext.JS_IN_ATTR,
        char_probe=probe,
        marker="ixm1234abcd",
        quote_char="'",
        limit=12,
    )
    comma = [p for p in payloads if p.startswith("1',")]
    assert comma, payloads
    assert comma[0] == "1',alert('ixm1234abcd'),'"
