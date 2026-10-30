"""DOM flow detection must follow the shapes real pages use.

Every case here was a real miss against a lab: the flow existed, the scanner
saw nothing, and the parameter was declared dead. The static analyzer is the
only component that can find these — the server never echoes the value, so no
reflection check will ever fire.
"""

from intellixss.analysis.static_dom import (
    _payload_candidates,
    analyze_dom_flows,
    fragment_dom_finding,
)


def _page(js: str) -> str:
    return f"<html><body><div id=d>hi</div><script>{js}</script></body></html>"


def test_document_write_takes_a_tainted_call_argument():
    """``document.write('<img …' + q)`` — the taint is after the sink name."""
    js = (
        "function track(q){ document.write('<img src=\"/t.gif?s='+q+'\">'); }\n"
        "var q = new URLSearchParams(window.location.search).get('search');\n"
        "if (q) track(q);"
    )
    assert ("location.search", "document.write", "html") in analyze_dom_flows(_page(js))


def test_document_write_without_taint_is_not_a_flow():
    js = "function f(){ document.write('<b>static</b>'); } f();"
    assert analyze_dom_flows(_page(js)) == []


def test_jquery_attr_href_is_a_url_sink():
    """``.attr('href', v)`` writes the same attribute as ``.href = v``."""
    js = (
        "$(function(){ $('#back').attr('href', "
        "(new URLSearchParams(window.location.search)).get('returnPath')); });"
    )
    assert ("location.search", "jquery_attr_url", "src") in analyze_dom_flows(_page(js))


def test_jquery_constructor_is_a_selector_sink():
    """``$(value)`` parses markup and reaches Sizzle's selector engine."""
    js = (
        "$(window).on('hashchange', function(){ var p = "
        "$('h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');"
        " if (p) p.get(0).scrollIntoView(); });"
    )
    assert ("location.hash", "jquery_selector", "html") in analyze_dom_flows(_page(js))


def test_location_search_offers_both_the_attribute_and_tag_breakout():
    """``location.search`` does not always encode ``<``.

    Whether a tag can be opened depends on how the page reads the value and how
    the attacker types it: an ``<img>`` attribute-builder only lets the quote be
    closed, while a ``document.write('<option>' + v)`` builder hands the parser
    the value verbatim and needs ``</select>`` to free the markup. Offering only
    one shape guarantees a miss on the other, so both are present and the
    browser decides between them.
    """
    candidates = _payload_candidates("html", "document.write", "", "location.search")
    payloads = [p for p, _ in candidates]
    assert payloads, "no payload for a location.search html flow"
    # The attribute breakout leads: the page's element points at a resource
    # that loads, so an onerror payload installs cleanly and stays silent.
    assert "onload" in payloads[0] and "<" not in payloads[0], payloads[0]
    # A tag breakout must also be available, for element-builder sinks.
    assert any("</select>" in p for p in payloads), payloads


def test_selector_sink_gets_a_selector_shaped_payload():
    payloads = [p for p, _ in _payload_candidates("html", "jquery_selector")]
    assert payloads and ":has(" in payloads[0], payloads


def test_finding_uses_the_source_specific_payload():
    js = (
        "function track(q){ document.write('<img src=\"/t.gif?s='+q+'\">'); }\n"
        "var q = new URLSearchParams(window.location.search).get('search');\n"
        "if (q) track(q);"
    )
    finding = fragment_dom_finding("https://t.test/?search=1", _page(js), "ixm0a1b2c3d")
    assert finding is not None
    assert "<" not in finding.payload, finding.payload
    assert "ixm0a1b2c3d" in finding.payload
