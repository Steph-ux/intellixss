"""A scan does not write to the target unless it was told to.

The audit found that writes are broader than the documentation says: the stored
pass runs on every scan, with no switch, and the upload, JSON and GraphQL
plugins post too. Running the scanner against a production application to look
for reflected XSS therefore leaves records behind — reviews, feedback, uploaded
files — with no warning and nothing that undoes them.

The rule pinned here is the one the CLI must honour:

* a scan is **read-only by default**: no ``POST``, ``PUT``, ``PATCH`` or
  ``DELETE`` is sent, and the stored pass does not run;
* a scan asked for writes (``Config.writes = True``) behaves as before;
* the decision is taken in one place, so a new plugin cannot quietly bypass it.

The tests count what actually reaches the wire through the shared HTTP client
rather than trusting a flag, because the failure being fixed is a write that
happened despite nobody asking for it.
"""

import asyncio

from intellixss.config import Config


class _Recorder:
    """An HTTP client stand-in that records method and URL, and nothing else."""

    def __init__(self):
        self.calls = []
        self.headers = {}
        self.cookies = {}

    async def request(self, method, url, **kw):
        self.calls.append((method.upper(), url))
        return (200, "<html><body>ok</body></html>", {}, url)

    def methods_used(self):
        return [m for m, _ in self.calls]


def test_a_default_scan_is_read_only():
    assert Config().writes is False, "a scan must not write unless asked"


def test_the_write_gate_refuses_writes_by_default():
    from intellixss.scanner import orchestrator

    cfg = Config()
    assert orchestrator.writes_allowed(cfg) is False


def test_the_write_gate_allows_writes_when_requested():
    from intellixss.scanner import orchestrator

    assert orchestrator.writes_allowed(Config(writes=True)) is True


def test_the_gate_covers_every_method_that_changes_state():
    """A method not listed here would be the next bypass."""
    from intellixss.scanner.orchestrator import UNSAFE_METHODS

    assert {"POST", "PUT", "PATCH", "DELETE"} <= set(UNSAFE_METHODS)
    assert "GET" not in UNSAFE_METHODS
    assert "HEAD" not in UNSAFE_METHODS


def test_read_only_refuses_an_unsafe_method_before_it_is_sent():
    from intellixss.scanner.orchestrator import guarded_send

    rec = _Recorder()
    sent = asyncio.run(
        guarded_send(rec, Config(), "POST", "https://t.test/api/reviews", {})
    )
    assert sent is False, "the guard must report that it refused"
    assert rec.methods_used() == []


def test_read_only_sends_a_safe_method():
    from intellixss.scanner.orchestrator import guarded_send

    rec = _Recorder()
    sent = asyncio.run(guarded_send(rec, Config(), "GET", "https://t.test/", {}))
    assert sent is True
    assert rec.methods_used() == ["GET"]


def test_writes_enabled_sends_the_unsafe_method():
    from intellixss.scanner.orchestrator import guarded_send

    rec = _Recorder()
    sent = asyncio.run(
        guarded_send(rec, Config(writes=True), "POST", "https://t.test/api", {})
    )
    assert sent is True
    assert rec.methods_used() == ["POST"]
