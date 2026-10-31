"""The scan hands its session to the browser before the first confirmation.

The unit test above proves that the confirmer merges cookies. This one proves
that the scanner calls it: a configured cookie reaching ``set_cookies`` only
from a form login leaves every lab whose session is a configured cookie opening
its confirmations anonymously, and the sink is then unreachable for a reason
that has nothing to do with the payload.
"""

from __future__ import annotations

import inspect
import re

from intellixss.scanner.orchestrator import Scanner


def test_the_scan_offers_its_configured_cookie_to_the_browser():
    src = inspect.getsource(Scanner.scan)
    start = src.index("self.browser.start()")
    startup = src[start : start + 2000]
    assert re.search(r"self\.browser\.set_cookies\(", startup), (
        "the browser is never given the scan's cookie jar at startup"
    )


def test_the_cookie_offered_is_the_configured_one_not_only_the_login_jar():
    src = inspect.getsource(Scanner.scan)
    start = src.index("self.browser.start()")
    startup = src[start : start + 2000]
    assert "auth_cookies" in startup, (
        "the browser receives the post-login jar only; a configured cookie never arrives"
    )
