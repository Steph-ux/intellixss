"""The SVG-animation route is chosen when handlers *and* href are filtered out.

A target that removes ``onerror`` and ``href`` looks closed to every payload bank
that assumes one of the two survives. It isn't: the filter judges attribute
*names*, and ``attributeName``/``values`` are neither. The animator then writes
``href="javascript:…"`` into the DOM after the filter has finished, so the link
exists with a scheme the filter never saw.

These tests pin the payload *shape* and the activation flag, because a payload
that loads but is never clicked is indistinguishable from a rejected one and
would be reported as unconfirmed.
"""

from intellixss.scanner.orchestrator import (
    _SCHEME_SPELLINGS,
    _allowlist_attr_payloads,
    _needs_activation,
)

MARK = "ixm0a1b2c3d"


def test_no_attr_payload_carries_an_event_handler_or_a_raw_href():
    """The whole point: the markup must contain neither of the blocked names."""
    for payload in _allowlist_attr_payloads(MARK):
        lowered = payload.lower()
        assert " on" not in lowered, payload
        # ``attributeName=href`` is the *target* of the animation, not a link
        # the filter recognises; a bare ``href=`` attribute must never appear.
        assert " href=" not in lowered, payload
        assert "xlink:href=" not in lowered, payload
        assert "attributeName=href" in payload or "attributeName=href" in payload


def test_every_attr_payload_carries_the_marker_the_confirmer_waits_for():
    for payload in _allowlist_attr_payloads(MARK):
        assert MARK in payload, payload


def test_the_animated_link_is_flagged_as_needing_activation():
    """A click is required, so the confirmer must click rather than observe."""
    for payload in _allowlist_attr_payloads(MARK):
        assert _needs_activation(payload), payload


def test_the_scheme_is_carried_by_an_animatable_attribute():
    """``values`` and ``from`` both install the link; ``to`` does it via ``set``."""
    carriers = set()
    for payload in _allowlist_attr_payloads(MARK):
        for name in ("values=", "from=", "to="):
            if f"{name}javascript:" in payload or f"{name}java\tscript:" in payload:
                carriers.add(name)
    assert "values=" in carriers and "from=" in carriers, carriers


def test_a_filter_that_only_lowercases_the_scheme_is_still_bypassed():
    """The browser collapses tabs before it decides the scheme."""
    spellings = {p.split("javascript:")[0][-3:] for p in _allowlist_attr_payloads(MARK)}
    assert any("\t" in p for p in _allowlist_attr_payloads(MARK)), spellings
    assert "javascript:" in _SCHEME_SPELLINGS


def test_payloads_are_deduplicated():
    payloads = _allowlist_attr_payloads(MARK)
    assert len(payloads) == len(set(payloads))
