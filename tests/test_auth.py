from intellixss.auth import (
    AuthConfig,
    build_auth_cookies,
    build_auth_headers,
    parse_cookie_string,
    parse_header_string,
)


def test_parse_cookie():
    c = parse_cookie_string("session=abc; csrf=xyz")
    assert c["session"] == "abc"
    assert c["csrf"] == "xyz"


def test_bearer_header():
    h = build_auth_headers(AuthConfig(bearer="tok123"))
    assert h["Authorization"] == "Bearer tok123"


def test_basic_header():
    h = build_auth_headers(AuthConfig(basic="user:pass"))
    assert h["Authorization"].startswith("Basic ")


def test_custom_header():
    h = parse_header_string("X-Api-Key: secret")
    assert h["X-Api-Key"] == "secret"


def test_cookies_from_auth():
    c = build_auth_cookies(AuthConfig(cookie="a=1; b=2"))
    assert c == {"a": "1", "b": "2"}
