"""Browser confirmer unit structure (no live Chromium required for import)."""

from intellixss.config import Config
from intellixss.verify.browser import BrowserConfirmer, BrowserConfirmResult, PLAYWRIGHT_AVAILABLE


def test_browser_confirm_result_defaults():
    r = BrowserConfirmResult(False, "no_dialog")
    assert r.confirmed is False
    assert r.detail == "no_dialog"


def test_confirmer_respects_use_browser_false():
    cfg = Config(use_browser=False)
    c = BrowserConfirmer(cfg)
    # start without launching when disabled path handled by scanner; module still constructs
    assert c.available is False


def test_playwright_flag_is_bool():
    assert isinstance(PLAYWRIGHT_AVAILABLE, bool)
