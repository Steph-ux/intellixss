"""A configured cookie is the session the browser must use.

Every browser confirmation navigates to the injected URL. On a lab whose sink
sits on an authenticated page the page is fetched anonymously first, and the
confirmation then lands on a login page instead of the sink — the lab is
reported clean even though the payload travels exactly where it should.

The HTTP client already holds the configured cookie (it is applied to the
session's jar in ``__aenter__``), so the browser must be given the same jar,
not only the cookies a *form login* happened to produce.
"""

from intellixss.auth import AuthConfig, build_auth_cookies
from intellixss.config import Config
from intellixss.verify.browser import BrowserConfirmer


def test_a_configured_cookie_is_what_the_browser_receives():
    auth = AuthConfig(cookie="session=abc123; csrftoken=def456")
    b = BrowserConfirmer(Config(use_browser=True))
    b.set_cookies(build_auth_cookies(auth))
    assert b._session_cookies == {"session": "abc123", "csrftoken": "def456"}


def test_the_jar_and_the_configured_cookie_are_merged_not_replaced():
    """A form login must add to the configured cookie, never drop it."""
    auth = AuthConfig(cookie="session=abc123")
    b = BrowserConfirmer(Config(use_browser=True))
    b.set_cookies(build_auth_cookies(auth))
    b.set_cookies({"JSESSIONID": "xyz"})
    assert b._session_cookies["session"] == "abc123"
    assert b._session_cookies["JSESSIONID"] == "xyz"
