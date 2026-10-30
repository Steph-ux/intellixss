"""Payload survival in URL attributes and the marker gate on browser candidates."""

from intellixss.models import CharProbeResult, InjectionContext
from intellixss.payloads.generator import generate_payloads

# What xss-game level 5 reports: the app entity-encodes every quote it sees.
ENCODING_PROBE = CharProbeResult(
    param="next",
    reflected=True,
    encoded_chars={"'": "&#39;", '"': "&quot;", "<": "&lt;", ">": "&gt;"},
)


def test_javascript_url_survives_a_quote_encoding_app():
    """The quotes live in the payload's script body, not in the attribute
    delimiter, so encoding them must not discard the payload."""
    payloads = generate_payloads(
        InjectionContext.HTML_ATTR_HREF,
        char_probe=ENCODING_PROBE,
        marker="ixm1234abcd",
        quote_char='"',
        limit=10,
    )
    assert payloads[0] == "javascript:alert('ixm1234abcd')", payloads


def test_data_url_survives_angle_bracket_encoding():
    payloads = generate_payloads(
        InjectionContext.HTML_ATTR_HREF,
        char_probe=ENCODING_PROBE,
        marker="ixm1234abcd",
        quote_char='"',
        limit=20,
    )
    assert any(p.startswith("data:text/html,") for p in payloads), payloads


def test_comma_expression_survives_quote_encoding():
    probe = CharProbeResult(
        param="timer",
        reflected=True,
        encoded_chars={"'": "&#39;", '"': "&quot;"},
    )
    payloads = generate_payloads(
        InjectionContext.JS_IN_ATTR,
        char_probe=probe,
        marker="ixm1234abcd",
        quote_char="'",
        limit=12,
    )
    assert "1',alert('ixm1234abcd'),'" in payloads, payloads


def test_unmarked_candidates_are_never_tried_by_mark_of():
    """Browser confirmation requires the marker: a candidate without it can
    only produce an unattributable dialog."""
    from intellixss.models import mark_of

    assert mark_of("1' onerror='alert(1)") == ""
    assert mark_of("1' onerror='alert('ixm12345678')") == "ixm12345678"
