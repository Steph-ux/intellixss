"""A sink behind a login is only reachable with a session, and only once.

Three things decide whether an authenticated scan works, and each was broken in a
different way:

* ``parse_cookie_string`` turned ``SameSite=None`` into a cookie named
  ``SameSite``, because a pasted ``Set-Cookie`` value has attributes as well as
  cookies. The server then received a header it never issued.
* ``_is_login_redirect`` has to distinguish "the site sent me to its login" from
  any other redirect; a trailing-slash normalisation is not an authentication
  challenge.
* The confirmer opens its own pages, so the session has to be handed to it
  explicitly or every browser confirmation is made as an anonymous visitor.
"""

from intellixss.auth import parse_cookie_string
from intellixss.scanner.orchestrator import (
    _form_fields,
    _is_login_redirect,
    _pass_field,
    _user_field,
)
from intellixss.verify.browser import BrowserConfirmer

from intellixss.config import Config

LOGIN_FORM = """
<form class="login-form" action="/login" method="POST">
  <input required type="hidden" name="csrf" value="abc">
  <input required type=username name="username" autofocus>
  <input required type=password name="password">
  <button class="button" type="submit"> Log in </button>
</form>
"""


def test_cookie_attributes_are_not_turned_into_cookies():
    parsed = parse_cookie_string("session=abc123; Secure; HttpOnly; SameSite=None")
    assert parsed == {"session": "abc123"}


def test_a_plain_cookie_header_still_parses_every_pair():
    assert parse_cookie_string("a=1; b=2") == {"a": "1", "b": "2"}


def test_a_value_containing_an_equals_sign_keeps_it():
    assert parse_cookie_string("token=ab=cd") == {"token": "ab=cd"}


def test_a_login_redirect_is_recognised_by_path_not_by_status():
    assert _is_login_redirect("https://x.test/post?postId=1", "https://x.test/login")
    assert _is_login_redirect("https://x.test/", "https://x.test/users/sign_in")


def test_a_trailing_slash_normalisation_is_not_a_login_redirect():
    assert not _is_login_redirect("https://x.test/account", "https://x.test/account/")


def test_a_redirect_that_keeps_the_path_is_not_a_login_redirect():
    assert not _is_login_redirect("https://x.test/my-account", "https://x.test/my-account?id=1")
    assert not _is_login_redirect("https://x.test/", "https://x.test/post?postId=2")


def test_a_cross_host_redirect_is_not_a_login_redirect():
    assert not _is_login_redirect("https://a.test/", "https://b.test/login")


def test_the_password_bearing_form_is_the_one_read():
    page = '<form action="/search"><input name="q"></form>' + LOGIN_FORM
    fields = _form_fields(page)
    assert fields == ["csrf", "username", "password"]


def test_the_named_fields_are_picked_out_of_the_form():
    fields = _form_fields(LOGIN_FORM)
    assert _user_field(fields) == "username"
    assert _pass_field(fields) == "password"


def test_an_email_login_is_recognised_without_the_word_username():
    page = '<form><input type=email name="email"><input type=password name="pass"></form>'
    fields = _form_fields(page)
    assert _user_field(fields) == "email"
    assert _pass_field(fields) == "pass"


def test_a_page_without_a_form_yields_no_fields():
    assert _form_fields("<p>nothing here</p>") == []


def test_the_confirmer_accepts_a_session_for_later_pages():
    confirmer = BrowserConfirmer(Config())
    assert confirmer._session_cookies == {}
    confirmer.set_cookies({"session": "abc"})
    assert confirmer._session_cookies == {"session": "abc"}
