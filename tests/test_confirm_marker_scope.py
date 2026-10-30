"""The confirmer must fire the element carrying our marker, not the first one.

A comment thread repeats the author ``onclick`` once per comment. Clicking the
first element with that handler exercises somebody else's link: the dialog that
follows (if any) announces a different value, and the payload under test never
runs. The selector therefore has to be scoped by the marker.
"""

import inspect

from intellixss.verify import browser as B


def test_fire_event_takes_the_marker():
    params = inspect.signature(B.BrowserConfirmer._fire_event).parameters
    assert "marker" in params


def test_fire_event_scopes_the_selector_by_marker():
    # The code moved to ``fire_handler`` (``_fire_event`` is now a thin bool
    # adapter), so the selector claim is checked where the selector is built.
    src = inspect.getsource(B.BrowserConfirmer.fire_handler)
    assert '"on{event}*="' in src or "on{event}*=" in src
    assert "el.click()" in src and "document.querySelector(sel)" in src


def test_fire_event_still_reports_a_boolean():
    # ``from __future__ import annotations`` makes the annotation a string.
    assert inspect.signature(B.BrowserConfirmer._fire_event).return_annotation in (bool, "bool")


def test_interactions_pass_the_marker_down():
    src = inspect.getsource(B.BrowserConfirmer._try_interactions)
    assert "_fire_event(page, handler, marker)" in src
