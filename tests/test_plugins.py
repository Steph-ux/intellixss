"""Plugin helpers pure logic."""

from intellixss.plugins.redirect_xss import _set_param, REDIRECT_PARAMS


def test_set_param_injects():
    u = _set_param("https://ex.com/a?x=1", "next", "javascript:alert(1)")
    assert "next=" in u
    assert "javascript" in u


def test_redirect_param_list_nonempty():
    assert "next" in REDIRECT_PARAMS
    assert "redirect" in REDIRECT_PARAMS
