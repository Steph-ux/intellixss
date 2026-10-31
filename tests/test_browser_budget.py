"""The browser budget is spent in priority order, and never over its cap.

Two properties matter under concurrency, because confirmations are awaited from
several scan tasks at once:

- A caller that checks the budget and a caller that spends it must not both see
  the same remaining slot, or the host is navigated one time more than the cap
  allows.
- A route the bundle only suggests must not take the last slots from a sink the
  scan has already written and read back. On Juice Shop the speculative hash
  routes spent the remainder of a 12-navigation cap and the review sink, which
  had been proven on the wire, was left unconfirmed.
"""

import asyncio

import pytest

from intellixss.config import Config
from intellixss.verify.browser import BrowserConfirmer

BASE = "http://127.0.0.1:3000"


def confirmer(cap: int) -> BrowserConfirmer:
    # No browser is started: only the bookkeeping is under test.
    return BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=cap))


def test_a_host_is_never_navigated_past_its_cap():
    b = confirmer(3)
    assert [b._take_slot(BASE, speculative=True) for _ in range(5)] == [
        True, True, True, False, False
    ]


def test_speculative_probes_stop_before_the_reserve_is_spent():
    b = confirmer(6)
    # With a reserve of 2, four slots are available to speculative probes and
    # the last two belong to evidence-backed confirmations.
    taken = [b._take_slot(BASE, speculative=True, reserve=2) for _ in range(6)]
    assert taken == [True, True, True, True, False, False]
    assert b._take_slot(BASE, speculative=False) is True
    assert b._take_slot(BASE, speculative=False) is True
    assert b._take_slot(BASE, speculative=False) is False


def test_an_uncapped_host_still_has_a_budget():
    b = confirmer(0)
    assert b.budget_left(BASE) == 1 << 30
    assert b._take_slot(BASE, speculative=True) is True


def test_concurrent_takers_cannot_overspend_one_slot():
    """Two coroutines that reach the check together must not both pass."""
    b = confirmer(1)
    gate = asyncio.Event()

    async def take():
        await gate.wait()
        return b._take_slot(BASE, speculative=True)

    async def run():
        tasks = [asyncio.create_task(take()) for _ in range(8)]
        gate.set()
        return await asyncio.gather(*tasks)

    assert sum(asyncio.run(run())) == 1


@pytest.mark.parametrize("reserve", [0, 1, 4])
def test_the_reserve_is_a_floor_for_speculative_probes(reserve):
    b = confirmer(12)
    granted = 0
    while b._take_slot(BASE, speculative=True, reserve=reserve):
        granted += 1
    assert granted == 12 - reserve
