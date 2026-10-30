"""A stored value can land in several places, and only one of them executes.

The comment form of the onclick lab writes the "website" value into the author
link twice: once as the ``href`` and once inside ``track('…')`` in the
``onclick`` handler. Each fix below was forced by a measurement on that page,
so each is pinned here.
"""

import pytest

from intellixss.analysis.context import _analyze_at, analyze_marker
from intellixss.models import InjectionContext
from intellixss.plugins.stored_xss import _build_payloads, _js_breakouts, _sink_contexts

MARKER = "ixmabcd1234"

# The shape of the author link once our value has been stored. ``&apos;`` is the
# entity spelling that reaches the handler as a bare quote.
AUTHOR_LINK = (
    '<p><a id="author" href="http://x&apos;);alert(`ixmabcd1234`);//" '
    'onclick="var tracker={track(){}};'
    "tracker.track('http://x&apos;);alert(`ixmabcd1234`);//');\">bob</a> | date</p>"
    "<p>a comment body</p>"
)


def test_plain_text_after_a_js_handler_is_not_inside_that_handler():
    """The handler's closing quote must end the attribute.

    Before this, the JS sub-state consumed ``onclick="…"``'s own closing quote
    as a string character, so the walker never left the attribute and a
    ``<p>`` comment body twenty tags later was classified as ``js_in_attr``.
    """
    html = "<p>zz ixkcommen zz</p>"
    i = html.find("ixkcommen")
    hit = _analyze_at(html, "ixkcommen", i, i + 9)
    assert hit.context == InjectionContext.HTML_TEXT


def test_text_after_a_closed_handler_attribute_is_text():
    html = AUTHOR_LINK + "<p>ixkcommen</p>"
    i = html.find("ixkcommen")
    assert _analyze_at(html, "ixkcommen", i, i + 9).context == InjectionContext.HTML_TEXT


def test_marker_inside_the_handler_is_still_js_in_attr():
    """The fix must not flatten the case it was written around."""
    i = AUTHOR_LINK.find("ixmabcd1234", AUTHOR_LINK.find("onclick"))
    hit = _analyze_at(AUTHOR_LINK, "ixmabcd1234", i, i + len("ixmabcd1234"))
    assert hit.context in (InjectionContext.JS_IN_ATTR, InjectionContext.JS_STRING_SINGLE)


def test_a_stored_value_rendered_twice_offers_both_sinks():
    """``href`` comes first in the document, the handler is what a click runs."""
    sinks = _sink_contexts(AUTHOR_LINK, "ixmabcd1234", InjectionContext.HTML_ATTR_HREF)
    assert InjectionContext.JS_IN_ATTR in sinks
    assert InjectionContext.HTML_ATTR_HREF in sinks
    # The handler leads: it fires on the very click that would follow the link.
    assert sinks[0] != InjectionContext.HTML_ATTR_HREF


def test_js_sink_builds_breakouts_not_markup():
    payloads = _build_payloads(MARKER, 8, InjectionContext.JS_IN_ATTR)
    assert payloads
    assert all("<" not in p for p in payloads), payloads
    assert any("&apos;" in p for p in payloads), payloads


def test_breakouts_stay_link_shaped_for_a_validating_field():
    """The field rejects anything that is not a URL, so every test lead is one."""
    for payload in _js_breakouts("alert('x')", MARKER):
        assert "://" in payload, payload


def test_entity_breakout_balances_the_handler():
    """``//`` closes the tail; the alert sits outside the string it broke."""
    payloads = _js_breakouts("alert('x')", MARKER)
    assert any(p.startswith("http://x&apos;);") for p in payloads), payloads
    assert all(p.count("`") % 2 == 0 for p in payloads if "`" in p), payloads


def test_href_family_is_unaffected():
    payloads = _build_payloads(MARKER, 4, InjectionContext.HTML_ATTR_HREF)
    assert payloads[0].startswith("javascript:")
    assert analyze_marker(AUTHOR_LINK, MARKER).occurrences
