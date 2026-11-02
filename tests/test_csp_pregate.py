"""The CSP pre-gate skips a doomed browser navigation.

When a finding's own page carries an enforced strict CSP, no inline payload the
scanner injects can execute, so the browser confirmation can only time out to
"no execution". The pre-gate must skip the navigation entirely (the real-world
time win) and flag the finding for reclassification — while leaving a page with
``'unsafe-inline'`` to be confirmed normally.
"""

import asyncio

from intellixss.config import Config
from intellixss.models import ContextAnalysis, InjectionContext, XSSFinding, _CspInfo
from intellixss.scanner.orchestrator import Scanner


class _FakeBrowser:
    def __init__(self):
        self.available = True
        self.calls = 0

    async def confirm(self, *a, **k):  # pragma: no cover - only if gate fails
        self.calls += 1
        from intellixss.verify.browser import BrowserConfirmResult

        return BrowserConfirmResult(False, "no_execution_observed")


def _finding():
    return XSSFinding(
        url="http://host/page?q=<svg/onload=alert(1)>",
        parameter="q",
        method="GET",
        context=InjectionContext.HTML_TEXT,
        payload="<svg/onload=alert('ixmdead99')>",
        marker="ixmdead99",
        evidence="reflected raw",
        vulnerability_type="reflected",
        verified_by="reflection",
    )


def _scanner_with_csp(csp):
    s = Scanner(Config(use_browser=True))
    s.browser = _FakeBrowser()
    s._csp_by_page = {"http://host/page": csp}  # pre-seed: no network needed
    return s


def test_enforced_strict_skips_browser():
    s = _scanner_with_csp(
        _CspInfo(present=True, strict=True, report_only=False, effective_script_src="'none'")
    )
    f = _finding()
    asyncio.run(s._confirm_with_browser(f, ContextAnalysis(context=InjectionContext.HTML_TEXT)))
    assert s.browser.calls == 0, "the browser navigation must be skipped under enforced strict CSP"
    assert id(f) in s._csp_gated_ids
    assert not f.browser_confirmed
    assert "csp-strict" in f.evidence and "'none'" in f.evidence


def test_report_only_still_confirms():
    s = _scanner_with_csp(
        _CspInfo(present=True, strict=True, report_only=True, effective_script_src="'none'")
    )
    f = _finding()
    asyncio.run(s._confirm_with_browser(f, ContextAnalysis(context=InjectionContext.HTML_TEXT)))
    assert s.browser.calls >= 1, "a Report-Only policy enforces nothing — confirm normally"
    assert id(f) not in s._csp_gated_ids


def test_unsafe_inline_still_confirms():
    s = _scanner_with_csp(
        _CspInfo(
            present=True, strict=False, report_only=False,
            effective_script_src="'self' 'unsafe-inline'",
        )
    )
    f = _finding()
    asyncio.run(s._confirm_with_browser(f, ContextAnalysis(context=InjectionContext.HTML_TEXT)))
    assert s.browser.calls >= 1, "a policy with 'unsafe-inline' does not block — confirm normally"
    assert id(f) not in s._csp_gated_ids
