"""The stored pass must reach write targets the per-target pass cannot.

A form is a ``POST``: the reflected pass drives it on the page that carries it.
An API is not a form — ``PUT /rest/products/1/reviews`` stores a record from a
bundle-discovered call and has no page to drive — so it is only reachable from
the stored pass. That pass used to return as soon as *any* stored finding
existed, which meant one form sink hid every API sink behind it.
"""

import asyncio
from types import SimpleNamespace

from intellixss.config import Config
from intellixss.models import InjectionContext, ScanResult, ScanTarget, XSSFinding
from intellixss.plugins import stored_xss
from intellixss.scanner import orchestrator


def _stored_finding(url: str, param: str) -> XSSFinding:
    return XSSFinding(
        url=url,
        parameter=param,
        method="POST",
        context=InjectionContext.HTML_TEXT,
        payload="<img src=x onerror=alert('ixm00000000')>",
        evidence="stored",
        vulnerability_type="stored",
        verified_by="browser",
        browser_confirmed=True,
        marker="ixm00000000",
    )


def test_put_target_is_scanned_after_a_post_form_already_stored():
    """A finding that already exists narrows the pass to writes that are not forms."""
    calls = []

    async def fake_auto(client, seed, *, browser=None, targets=None, log=None, page_stages=True):
        calls.append(
            (browser, page_stages, [(t.method, t.url) for t in targets or []])
        )
        return []

    # Writing is what this test is about, so the scan is asked for it
    # explicitly. Read-only is the default and drops these targets on purpose,
    # which is covered below.
    scanner = orchestrator.Scanner(Config(writes=True))
    scanner._mute = True
    result = ScanResult(target_url="https://t.test/")
    result.findings.append(_stored_finding("https://t.test/api/Complaints", "message"))
    targets = [
        ScanTarget(
            url="https://t.test/api/Complaints",
            method="POST",
            params=["message"],
            data={"message": "test"},
            source="js_write",
        ),
        ScanTarget(
            url="https://t.test/rest/products/1/reviews",
            method="PUT",
            params=["message"],
            data={"message": "test"},
            source="js_write",
        ),
    ]

    saved = orchestrator.scan_stored_auto
    orchestrator.scan_stored_auto = fake_auto
    try:
        asyncio.run(
            scanner._stored_pass(
                SimpleNamespace(), "https://t.test/", targets, result, asyncio.Lock()
            )
        )
    finally:
        orchestrator.scan_stored_auto = saved

    assert calls, "the stored pass must still run for the API target"
    browser, page_stages, urls = calls[0]
    # A stored sink already exists, so the form stages are skipped; the browser
    # is kept because an API sink is confirmed by rendering the page that reads
    # it back.
    assert page_stages is False
    assert browser is scanner.browser
    assert urls == [("PUT", "https://t.test/rest/products/1/reviews")]


def test_full_stored_pass_runs_when_nothing_was_stored_yet():
    calls = []

    async def fake_auto(client, seed, *, browser=None, targets=None, log=None, page_stages=True):
        calls.append((browser, page_stages, len(targets or [])))
        return []

    scanner = orchestrator.Scanner(Config(writes=True))
    scanner._mute = True
    result = ScanResult(target_url="https://t.test/")
    targets = [
        ScanTarget(url="https://t.test/api/Complaints", method="POST", params=["message"]),
        ScanTarget(url="https://t.test/rest/products/1/reviews", method="PUT", params=["message"]),
    ]

    saved = orchestrator.scan_stored_auto
    orchestrator.scan_stored_auto = fake_auto
    try:
        asyncio.run(
            scanner._stored_pass(
                SimpleNamespace(), "https://t.test/", targets, result, asyncio.Lock()
            )
        )
    finally:
        orchestrator.scan_stored_auto = saved

    assert calls == [(scanner.browser, True, 2)]


def test_a_read_only_scan_never_hands_a_write_target_to_the_pass():
    """The default scan drives the page, not the API that stores the record."""
    calls = []

    async def fake_auto(client, seed, *, browser=None, targets=None, log=None, page_stages=True):
        calls.append(
            (page_stages, [(t.method, t.url) for t in targets or []])
        )
        return []

    scanner = orchestrator.Scanner(Config())  # read-only
    scanner._mute = True
    result = ScanResult(target_url="https://t.test/")
    targets = [
        ScanTarget(url="https://t.test/api/Complaints", method="POST", params=["message"]),
        ScanTarget(url="https://t.test/rest/products/1/reviews", method="PUT", params=["message"]),
        ScanTarget(url="https://t.test/search", method="GET", params=["q"]),
    ]

    saved = orchestrator.scan_stored_auto
    orchestrator.scan_stored_auto = fake_auto
    try:
        asyncio.run(
            scanner._stored_pass(
                SimpleNamespace(), "https://t.test/", targets, result, asyncio.Lock()
            )
        )
    finally:
        orchestrator.scan_stored_auto = saved

    assert calls, "the page stages must still run on a read-only scan"
    page_stages, urls = calls[0]
    assert page_stages is True
    assert urls == [("GET", "https://t.test/search")]
