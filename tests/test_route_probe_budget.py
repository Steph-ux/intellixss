"""A route the bundle only suggests may not spend the slot a proven sink needs.

The scanner confirms sinks in the order the scan reaches them, and the browser
budget per host is small on purpose. A bundle can name a dozen hash routes ahead
of the sink that was actually written and read back, so the speculative probes
have to leave part of the host for the evidence that follows — but leaving *all*
of it means the guesses never run and a route that would have fired is refused
for nothing.

The probe is called directly, once per route, as the orchestrator does; what is
under test is the accounting inside it, not the route deduplication above it.
"""

import asyncio

from intellixss.config import Config
from intellixss.scanner.orchestrator import (
    Scanner,
    _probe_reserve,
    _ROUTE_ATTEMPT_ALLOWANCE,
)
from intellixss.verify.browser import _SPECULATIVE_RESERVE, BrowserConfirmer

BASE = "http://127.0.0.1:3000"


class _FakeBrowser:
    """The budget bookkeeping a route probe touches, without Playwright."""

    available = True

    def __init__(self, cap: int):
        self._real = BrowserConfirmer(Config(use_browser=True, max_confirm_per_host=cap))
        self.confirmations = 0
        self.speculative_flags = []

    def can_spend(self, url, *, speculative=False, reserve=0):
        return self._real.can_spend(url, speculative=speculative, reserve=reserve)

    def _take_slot(self, url, *, speculative=False, reserve=0):
        return self._real._take_slot(url, speculative=speculative, reserve=reserve)

    def budget_left(self, url):
        return self._real.budget_left(url)

    async def confirm(self, url, speculative=False, kind="", **kwargs):
        # One navigation, one slot: the slot is charged here and nowhere else.
        # The browser is given the reserve the probe arranged — the same number
        # the probe asked ``can_spend`` with — so a probe that navigates when it
        # should have stopped is caught, rather than being saved by a floor the
        # browser picked for itself.
        self.speculative_flags.append(speculative)
        if not self._real._take_slot(
            url, speculative=speculative, reserve=kwargs.get("reserve", 1)
        ):
            raise AssertionError("confirm reached with no slot left on the host")
        self.confirmations += 1
        return type(
            "B",
            (),
            {
                "confirmed": False,
                "detail": "no_execution_observed",
                "trigger": "",
                "dialog_message": "",
                "marker_echoed": False,
            },
        )()


class _Result:
    """The slice of a scan result a route probe writes to."""

    def __init__(self):
        self.stats = type("S", (), {"requests": 0})()
        self.findings = []
        self.diagnoses = []
        self.waf = ""

    def add_finding(self, finding):
        self.findings.append(finding)


def _probe(browser, calls: int) -> None:
    scanner = Scanner(Config(guess_params=True, use_browser=True))
    scanner._mute = True
    scanner.browser = browser
    # One target per call, so nothing above the probe can answer for a route
    # the scan has already asked about.
    targets = [
        type(
            "T",
            (),
            {
                "url": f"{BASE}/#/route{i}",
                "method": "GET",
                "params": ["q"],
                "source": "client_route",
            },
        )()
        for i in range(calls)
    ]
    result = _Result()

    async def run():
        lock = asyncio.Lock()
        for target in targets:
            await scanner._scan_client_route(None, target, "q", result, lock)

    asyncio.run(run())


def test_the_reserve_never_takes_the_whole_host():
    # A fixed floor is the whole budget on a small host: two of six slots
    # reserved leaves eight routes nothing to prove, and the reserve was there
    # for the sink, not to starve the route that fires.
    browser = _FakeBrowser(cap=12)
    assert _probe_reserve(browser, BASE) == _SPECULATIVE_RESERVE
    browser = _FakeBrowser(cap=4)
    assert _probe_reserve(browser, BASE) == 2
    browser = _FakeBrowser(cap=2)
    assert _probe_reserve(browser, BASE) == 1
    browser = _FakeBrowser(cap=0)
    assert _probe_reserve(browser, BASE) >= 1


def test_a_probe_checks_the_reserve_before_it_navigates():
    """The probe's guard is what has to hold; the browser is only obeying it."""

    class _AsksFirst:
        available = True

        def __init__(self):
            self.asked, self.confirmed = 0, 0

        def budget_left(self, url):
            return 12

        def can_spend(self, url, *, speculative=False, reserve=0):
            self.asked += 1
            assert speculative is True
            # The configured floor, since the host still has more than twice
            # that left; on a smaller host the floor shrinks with it.
            assert reserve == _SPECULATIVE_RESERVE
            return False

        async def confirm(self, url, **kwargs):
            self.confirmed += 1
            raise AssertionError("a probe the budget refuses must not navigate")

    scanner = Scanner(Config(guess_params=True, use_browser=True))
    scanner._mute = True
    browser = _AsksFirst()
    scanner.browser = browser
    target = type(
        "T",
        (),
        {"url": f"{BASE}/#/route", "method": "GET", "params": ["q"], "source": "client_route"},
    )()
    result = _Result()

    asyncio.run(scanner._scan_client_route(None, target, "q", result, asyncio.Lock()))

    assert browser.asked == 1
    assert browser.confirmed == 0
    assert result.stats.requests == 0


def test_probes_leave_part_of_a_small_host_for_the_evidence():
    # A host whose whole budget is two cannot give its reserve away to the
    # probes: the smallest floor is one slot, and the guess takes the other.
    browser = _FakeBrowser(cap=2)
    _probe(browser, calls=1)

    assert browser.confirmations == 1
    assert browser.budget_left(BASE) == 1
    assert browser.budget_left(BASE) >= _probe_reserve(browser, BASE)


def test_one_probe_costs_exactly_one_navigation():
    browser = _FakeBrowser(cap=12)
    _probe(browser, calls=1)
    assert browser.confirmations == 1
    assert browser.budget_left(BASE) == 11


def test_the_navigation_is_marked_speculative_so_the_browser_holds_the_reserve():
    # The guard above is the caller's courtesy; the browser has to refuse on its
    # own as well, or a route reached on another path spends the reserve.
    browser = _FakeBrowser(cap=6)
    _probe(browser, calls=1)
    assert browser.speculative_flags == [True]


def test_a_proven_sink_can_still_take_the_reserved_slots():
    browser = _FakeBrowser(cap=12)
    _probe(browser, calls=1)
    left = browser.budget_left(BASE)
    assert left == 11

    # An evidence-backed confirmation is not speculative, so every slot the
    # routes left is reachable.
    taken = [browser._take_slot(f"{BASE}/rest/x", speculative=False) for _ in range(left)]
    assert taken == [True] * left
    assert browser._take_slot(f"{BASE}/rest/x", speculative=False) is False

def test_a_route_already_probed_is_not_probed_again():
    """A second pass over the same key must not buy another navigation.

    The scan reaches a route from the per-target pass and again from any later
    pass that walks the same targets; the second attempt has learned nothing to
    justify a second navigation on a host whose budget is twelve.
    """
    browser = _FakeBrowser(cap=12)
    scanner = Scanner(Config(guess_params=True, use_browser=True))
    scanner._mute = True
    scanner.browser = browser
    target = type(
        "T",
        (),
        {"url": f"{BASE}/#/search", "method": "GET", "params": ["q"], "source": "client_route"},
    )()
    result = _Result()

    async def run():
        lock = asyncio.Lock()
        for _ in range(_ROUTE_ATTEMPT_ALLOWANCE + 2):
            await scanner._scan_client_route(None, target, "q", result, lock)

    asyncio.run(run())

    assert browser.confirmations == _ROUTE_ATTEMPT_ALLOWANCE
