"""A probe may not take a slot a seeded flow is already waiting for.

The measurement: on the Juice Shop account page the browser budget of the host
was spent as ``route=8`` out of twelve, and ``last-login-ip`` — a flow whose
source is ``localStorage``, with its sink already named — ended as a lead
instead of a confirmation. The regex analyser found the flow; the browser had
no navigation left to prove it.

The reserve that exists today is a *fixed floor*: a probe is refused only when
fewer slots remain than :data:`_CLIENT_ROUTE_RESERVE`. It has no idea how many
seeded flows are actually queued, so eight guessed routes are enough to spend
the eight slots that were not reserved, whatever evidence is waiting behind
them.

The rule this file pins: the reserve a probe must respect is derived from the
number of seeded flows still to confirm, not from a constant. A host with three
seeded flows queued keeps three navigations, and a probe that would eat into
them is refused — deterministically, before it spends anything.
"""

from intellixss.config import Config
from intellixss.verify.browser import BrowserConfirmer


URL = "https://t.test/account"


def _confirmer(cap: int = 12) -> BrowserConfirmer:
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=cap))
    b.available = True
    return b


def test_a_probe_is_refused_when_queued_seeded_flows_need_the_slot():
    b = _confirmer()
    # Three seeded flows are waiting; the host has exactly three navigations.
    b.note_seeded_pending(URL, 3)
    for _ in range(9):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.budget_left(URL) == 3
    assert b.can_spend(URL, speculative=True, reserve=0) is False
    assert b.can_spend(URL, speculative=False) is True


def test_the_reserve_shrinks_as_seeded_flows_are_confirmed():
    b = _confirmer()
    b.note_seeded_pending(URL, 2)
    for _ in range(10):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.can_spend(URL, speculative=True, reserve=0) is False
    # One of the two is confirmed: only one slot is still protected.
    b.note_seeded_confirmed(URL)
    assert b.can_spend(URL, speculative=True, reserve=0) is True
    assert b.budget_left(URL) == 2


def test_no_queued_flow_means_the_old_behaviour_is_unchanged():
    b = _confirmer()
    for _ in range(8):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.can_spend(URL, speculative=True, reserve=0) is True


def test_the_explicit_reserve_still_applies_on_top():
    """A caller that asks for more protection than the queue needs keeps it."""
    b = _confirmer()
    for _ in range(10):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.can_spend(URL, speculative=True, reserve=2) is False
