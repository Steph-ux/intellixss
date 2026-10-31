"""A value in a URL attribute can declare a handler its own element fires.

The attribute is a real element, so the value can leave the URL grammar and
declare an event handler on it. What makes the handler reachable is the part
that took a real page to learn: a link strips its labels before it reaches the
accessibility tree, so an ``accesskey`` on it is never a keystroke, while
``autofocus`` is honoured and fires ``onfocus`` with no interaction at all.
"""

from intellixss.scanner.orchestrator import _attribute_shortcut_payloads


def test_the_first_payload_fires_without_a_click():
    first = _attribute_shortcut_payloads("ixm0123abcd", '"')[0]
    assert "autofocus" in first
    assert "onfocus=" in first


def test_a_label_based_shortcut_is_still_tried():
    # Not every element loses its labels: an image or a form control keeps
    # ``accesskey``, and it stays in the list for those.
    payloads = _attribute_shortcut_payloads("ixm0123abcd", '"')
    assert any("accesskey=" in p and "onclick=" in p for p in payloads)


def test_every_payload_starts_by_closing_the_attribute():
    for quote in ('"', "'"):
        for p in _attribute_shortcut_payloads("ixm0123abcd", quote):
            assert p.startswith(quote), p


def test_the_label_based_reading_is_not_what_credits_a_link():
    # The first payload is the one a link needs; it is what the lab measured.
    # Asserting the order keeps a later edit from burying it behind the
    # ``accesskey`` variants, which a link silently drops.
    first = _attribute_shortcut_payloads("ixm0123abcd", '"')[0]
    assert "autofocus" in first and "accesskey" not in first


def test_the_marker_is_called_with_backticks_only():
    # A second quote in the call would end the attribute a second time and make
    # the handler inert.
    for p in _attribute_shortcut_payloads("ixm0123abcd", '"'):
        assert "alert(`ixm0123abcd`)" in p, p
