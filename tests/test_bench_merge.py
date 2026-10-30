"""The bench must not lose a confirmed finding behind a reflection-only lead.

The same sink produces two findings: the reflection oracle reports the payload
it saw echoed, and the browser reports the one that actually ran. The bench
merges findings across pages, and an earlier version keyed that merge on
``(param, context)`` alone — so the second row overwrote the first and a
confirmed finding disappeared from the report while the unconfirmed lead stayed.

That is a measurement bug, and it made a working lab look CLEAN. These tests
pin the merge rule: distinct evidence quality is kept as distinct rows, and
when two pages report the same sink the better evidence wins.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _psbench import scan_one  # noqa: E402


class _Severity:
    def __init__(self, value):
        self.value = value


class _Ctx:
    def __init__(self, value):
        self.value = value


class _Finding:
    def __init__(self, param, ctx, verified_by):
        self.parameter = param
        self.context = _Ctx(ctx)
        self.verified_by = verified_by
        self.severity = _Severity("MEDIUM")
        self.payload = f"payload-{verified_by}"


class _Stats:
    requests = 1


class _Result:
    def __init__(self, findings):
        self.findings = findings
        self.stats = _Stats()


class _Scanner:
    """Records the findings the real merge will be given, without a network."""

    plans: list = []

    def __init__(self, _config):
        self._mute = False
        self.browser = self
        self._plan = None

    @property
    def available(self):
        return True

    async def scan(self, _url):
        # One plan per page, consumed in order: the harness grades what each
        # page reported, not a cached first answer.
        return _Result(self.plans.pop(0))

    async def stop(self):
        return None

@pytest.mark.asyncio
async def test_confirmed_finding_survives_the_reflection_lead(monkeypatch):
    import _psbench

    monkeypatch.setattr(_psbench, "Scanner", _Scanner)
    _Scanner.plans = [
        [
            _Finding("search", "html_attr_href", "reflection"),
            _Finding("search", "html_attr_href", "browser"),
        ]
    ]
    out = await scan_one("http://example.invalid/")
    assert [f["verified_by"] for f in out["findings"]] == ["browser"]


@pytest.mark.asyncio
async def test_later_browser_confirmation_replaces_the_earlier_lead(monkeypatch):
    import _psbench

    monkeypatch.setattr(_psbench, "Scanner", _Scanner)
    _Scanner.plans = [
        [_Finding("search", "html_attr_href", "reflection")],
        [_Finding("search", "html_attr_href", "browser")],
    ]
    out = await scan_one("http://example.invalid/", ["http://example.invalid/post?postId=2"])
    assert [f["verified_by"] for f in out["findings"]] == ["browser"]
    assert out["findings"][0]["page"].endswith("postId=2")
