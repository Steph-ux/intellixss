"""A quote-escaping server makes the marker reachable only without quotes.

The template-literal lab writes every ``'`` as ``\\u0027``. Inside a ``${…}``
interpolation that escape is not re-read as a quote, so ``alert('ixm…')``
silently never fires — while a call assembled from character codes runs
untouched. Three separate gates each dropped that payload for the same wrong
reason, so each is pinned here.
"""

from intellixss.models import ContextAnalysis, InjectionContext, mark_of
from intellixss.payloads.generator import (
    _mark_unquoted,
    generate_payloads,
    make_marker,
)

MARKER = "ixmabcd1234"
ESCAPED_BODY = (
    "var message = `0 search results for '${alert(\\u0027ixmabcd1234\\u0027)}'`;"
)


def _ctx() -> ContextAnalysis:
    return ContextAnalysis(
        context=InjectionContext.JS_TEMPLATE, quote_char=""
    )


def test_unquoted_call_carries_no_quote_character():
    call = _mark_unquoted(MARKER)
    assert "'" not in call and '"' not in call and "`" not in call
    assert f"alert({call[len('alert('):-1]})" == call
    assert "String.fromCharCode(" in call


def test_generator_offers_the_unquoted_interpolation():
    payloads = generate_payloads(
        InjectionContext.JS_TEMPLATE,
        None,
        limit=24,
        marker=make_marker("abcd1234"),
        quote_char="",
    )
    assert any(
        p.startswith("${alert(String.fromCharCode(") for p in payloads
    ), payloads


def test_mark_of_sees_the_marker_through_fromcharcode():
    payload = "${" + _mark_unquoted(MARKER) + "}"
    assert mark_of(payload) == MARKER


def test_mark_of_still_requires_a_real_marker():
    assert mark_of("${alert(String.fromCharCode(49,50,51))}") == ""
    assert mark_of("${alert('nothing here')}") == ""


def test_unicode_escaped_quote_counts_as_survival():
    from intellixss.analysis.reflection import escapes_in_place

    payload = "${alert('ixmabcd1234')}"
    assert escapes_in_place(ESCAPED_BODY, payload)


def test_interpolation_is_not_judged_by_chars_it_never_uses():
    """A blocked quote and bracket must not kill a quote-free interpolation."""
    from intellixss.scanner.orchestrator import _needs_blocked_chars

    payload = "${alert('ixmabcd1234')}"
    blocked = {"'", "<", ">"}
    assert _needs_blocked_chars(payload, blocked, blocked - {">"}) is False
