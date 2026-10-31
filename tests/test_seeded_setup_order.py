"""Seeded flows are found and declared before any route probe runs.

The mechanism in ``BrowserConfirmer`` protects a slot only if the queue is
declared *before* the probes start spending. In the scan loop the probes run
inside ``_scan_target`` on discovered parameters, while ``_scan_source_dom``
runs only after the whole reflected pass has finished — so on the Juice Shop
account page the eight route guesses were spent first and the seeded
``localStorage`` flow arrived with nothing left.

The ordering rule pinned here: the page's seeded flows are located and declared
once, before the parameter sweep, so their navigations are reserved for the
whole run rather than for the moment they happen to be confirmed.
"""

import asyncio

import pytest

from intellixss.config import Config
from intellixss.verify.browser import BrowserConfirmer


URL = "https://t.test/account"


def test_a_probe_cannot_spend_a_reservation_declared_up_front():
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=12))
    b.available = True
    # The page declares its seeded flows before the sweep begins.
    b.note_seeded_pending(URL, 2)
    spent = 0
    while b.can_spend(URL, speculative=True, reserve=0):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
        spent += 1
    # Ten probes at most: two navigations stay reserved for the seeded flows.
    assert spent == 10
    assert b.budget_left(URL) == 2


@pytest.mark.parametrize("queued", [1, 3, 5])
def test_the_reservation_tracks_the_number_queued(queued):
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=12))
    b.available = True
    b.note_seeded_pending(URL, queued)
    while b.can_spend(URL, speculative=True, reserve=0):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.budget_left(URL) == queued


def test_confirming_every_queued_flow_releases_every_slot():
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=12))
    b.available = True
    b.note_seeded_pending(URL, 2)
    b.note_seeded_confirmed(URL)
    b.note_seeded_confirmed(URL)
    # Nothing queued any more: the old rule applies and probes may spend all.
    while b.can_spend(URL, speculative=True, reserve=0):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.budget_left(URL) == 0


def test_an_empty_declaration_clears_a_previous_one():
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=12))
    b.available = True
    b.note_seeded_pending(URL, 3)
    b.note_seeded_pending(URL, 0)
    while b.can_spend(URL, speculative=True, reserve=0):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.budget_left(URL) == 0


def test_a_queued_flow_can_still_spend_its_own_reservation():
    """The reserved slots are not frozen: evidence is exactly what they are for."""
    b = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=12))
    b.available = True
    b.note_seeded_pending(URL, 1)
    for _ in range(11):
        b._take_slot(URL, speculative=True, reserve=0, kind="route")
    assert b.budget_left(URL) == 1
    assert b.can_spend(URL, speculative=False) is True
    assert b._take_slot(URL, kind="dom-source") is True
    assert b.budget_left(URL) == 0
