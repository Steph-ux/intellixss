"""A browser confirmation is causal or it does not happen.

The engine credits a finding only when a dialog carries the marker its own
payload injected. ``confirm`` used to fall back to "any dialog fired during the
observation window" when the caller passed a payload with no marker, which made
``alert(1)`` sufficient proof: a page that alerts for its own reasons, or a
payload another request left behind, confirmed just as well.

The fallback is what let five of the six plugins ship without a marker. The
contract these tests pin is the one the engine already documents: a dialog that
does not carry a marker proves nothing, so asking for a confirmation without
one is a caller defect and is refused before a navigation is spent.
"""

import asyncio

from intellixss.config import Config
from intellixss.payloads.generator import make_marker
from intellixss.verify.browser import BrowserConfirmer


class _Browser:
    """Just enough of a verifier to observe the decisions ``confirm`` makes."""

    def __init__(self):
        # No browser is started: the guard is decided before any page exists,
        # so what is under test is what ``confirm`` does with the arguments.
        base = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=4))
        self.__dict__.update(base.__dict__)
        # ``available`` is an instance attribute set when a browser starts, so
        # it has to be flipped after the copy, not on the class.
        self.available = True
        self._browser = object()
        self._sem = asyncio.Semaphore(1)
        self.navigations = []
        self.result = None

    async def goto(self, url, **_kw):
        self.navigations.append(url)
        return self.result


def _run(verifier, payload, marker=""):
    return asyncio.run(
        BrowserConfirmer.confirm(
            verifier, "https://t.test/x", payload=payload, marker=marker
        )
    )


def test_payload_without_a_marker_is_refused_not_confirmed():
    v = _Browser()
    res = _run(v, "alert(1)")
    assert res.confirmed is False
    assert res.detail == "confirm_without_marker"
    # The refusal costs nothing: no slot is taken for a probe that could not
    # prove anything even if it fired.
    assert v.navigations == []


def test_an_empty_payload_is_also_refused():
    v = _Browser()
    res = _run(v, "")
    assert res.confirmed is False
    assert res.detail == "confirm_without_marker"
    assert v.navigations == []


def test_a_marker_in_the_payload_is_still_accepted():
    # The guard must not reject the engine's own probe: every payload the
    # scan builds carries the marker, and that path has to keep navigating.
    v = _Browser()
    marker = make_marker("a1b2c3d4")
    v.reached, res = _past_the_guard(v, f"<img src=x onerror=alert('{marker}')>")
    assert v.reached, "a marked payload must still reach the page"
    assert res.detail != "confirm_without_marker"


def test_an_explicit_marker_is_honoured_even_if_absent_from_payload():
    # ``confirm_markup`` and the stored pass pass the marker explicitly; the
    # guard reads the same value ``_extract_marker`` would fall back to.
    v = _Browser()
    v.reached, res = _past_the_guard(v, "alert(1)", marker=make_marker("deadbeef"))
    assert v.reached
    assert res.detail != "confirm_without_marker"


def _past_the_guard(verifier, payload, marker=""):
    """Run ``confirm`` and report whether it got as far as opening the page.

    The positive cases are about the guard only, so the inner probe is stubbed:
    what is asserted is that a marked call is not stopped, not what a page
    does with it.
    """
    from intellixss.verify.browser import BrowserConfirmResult

    reached = []

    async def inner(url, **_kw):
        reached.append(url)
        return BrowserConfirmResult(True, "stub")

    verifier._confirm_inner = inner
    res = _run(verifier, payload, marker=marker)
    return bool(reached), res
