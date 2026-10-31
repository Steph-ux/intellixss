"""The stored pass runs before the browser stages that speculatively navigate.

The per-host browser budget is small on purpose, and the stages that spend it
are not equally justified. A stored sink was written and read back on the wire
before the browser is asked anything; a page stage is a guess about a source the
URL cannot drive — a route the bundle suggests, a value read from
``localStorage`` — and a handful of them will use a whole budget on their own.

Running the guesses first is how a proven sink ended a scan unconfirmed with
``confirm_budget_exhausted``. This pins the order: evidence, then guesses.
"""

import asyncio

from intellixss.config import Config
from intellixss.models import ScanResult, ScanTarget
from intellixss.scanner import orchestrator


def _run_scan_order() -> list:
    order = []

    async def fake_discover(client, url, config):
        return [
            ScanTarget(url="https://t.test/rest/products/1/reviews", method="PUT", params=["message"])
        ]

    async def fake_target(self, client, target, result, baseline_waf, lock):
        order.append("reflected")

    async def fake_source_dom(self, client, target, result, lock):
        order.append("page")

    async def fake_stored(self, client, target_url, targets, result, lock):
        order.append("stored")

    class _Client:
        """The seed request is all the HTTP this test needs to answer."""

        requests = 0

        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def request(self, method, url, **kw):
            return 200, "<html><body>shop</body></html>", {}, url

    saved = (
        orchestrator.discover_targets,
        orchestrator.HttpClient,
        orchestrator.Scanner._scan_target,
        orchestrator.Scanner._scan_source_dom,
        orchestrator.Scanner._stored_pass,
    )
    orchestrator.discover_targets = fake_discover
    orchestrator.HttpClient = _Client
    orchestrator.Scanner._scan_target = fake_target
    orchestrator.Scanner._scan_source_dom = fake_source_dom
    orchestrator.Scanner._stored_pass = fake_stored

    class _Browser:
        available = True

        async def start(self):
            pass

        async def stop(self):
            pass

    scanner = orchestrator.Scanner(Config())
    scanner._mute = True
    scanner.browser = _Browser()
    scanner.config.use_browser = True
    try:
        asyncio.run(scanner.scan("https://t.test/"))
    finally:
        (
            orchestrator.discover_targets,
            orchestrator.HttpClient,
            orchestrator.Scanner._scan_target,
            orchestrator.Scanner._scan_source_dom,
            orchestrator.Scanner._stored_pass,
        ) = saved
    return order


def test_the_stored_pass_precedes_the_page_stages():
    assert _run_scan_order() == ["reflected", "stored", "page"]


def test_a_stage_that_was_skipped_is_not_silently_reordered():
    """Guard against the test passing because a stage never ran at all."""
    order = _run_scan_order()
    assert set(order) == {"reflected", "stored", "page"}
