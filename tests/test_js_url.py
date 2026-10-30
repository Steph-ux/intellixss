"""A parameter validated as a number can still be spliced into executable code.

A lab takes ``postId``, rejects anything that is not an id, and builds
``<a href="javascript:fetch('/analytics', {body:'…postId…'})">``. No canary ever
survives the validator, so reflection-based detection declares the parameter
dead — yet the accepted value lands inside a script that the browser evaluates
on click. These tests pin the two things that make it detectable and usable:
the context is recognised as JS (not as a URL attribute), and the breakout is
built for the quote that is actually open.
"""

from intellixss.analysis.context import analyze_marker, _pseudo_prefix_viable
from intellixss.models import InjectionContext
from intellixss.scanner.orchestrator import _js_string_open_at, _js_url_payload

PAGE = (
    '<div class="is-linkback">'
    '<a href="javascript:fetch(\'/analytics\', {method:\'post\','
    "body:'/post%%3fpostId%%3d%s'}).finally(_ => window.location = '/')"
    '">Back to Blog</a></div>'
)


def _page(value: str) -> str:
    return PAGE % value


def test_javascript_url_is_a_script_context_not_a_url_attribute():
    hit = analyze_marker(_page("MARKER123"), "MARKER123")
    assert hit.context == InjectionContext.JS_STRING_SINGLE
    assert hit.quote_char == '"'  # the HTML attribute delimiter
    assert hit.js_string_quote == "'"  # the JS string actually broken


def test_ordinary_url_attribute_stays_a_url():
    html = '<a href="https://example.test/MARKER123">x</a>'
    hit = analyze_marker(html, "MARKER123")
    assert hit.context == InjectionContext.HTML_ATTR_HREF


def test_pseudo_scheme_prefix_viability():
    for viable in ("", "j", "java", "javascript:", "  javascript:"):
        assert _pseudo_prefix_viable(viable), viable
    for rejected in ("ht", "http://", "javascripX", "javascriptX", "x"):
        assert not _pseudo_prefix_viable(rejected), rejected


def test_open_string_is_identified_before_the_value():
    js = "fetch('/x', {body:'/post?postId=VALUE'})"
    assert _js_string_open_at(js, "VALUE") == "'"
    double = 'fetch("/x", {body:"/post?postId=VALUE"})'
    assert _js_string_open_at(double, "VALUE") == '"'
    code = "location.href = value + 1"
    assert _js_string_open_at(code, "value") == ""


def test_breakout_payload_shape():
    payload = _js_url_payload("ixm0a1b2c3d", "'", prefix="1")
    # Anchored on the page's own id so the validator sees the expected shape.
    assert payload.startswith("1&'")
    # The quote that is open gets closed; the marker is carried as a string so
    # a dialog echoing it proves our code ran.
    assert payload.count("'") == payload.count("'")
    assert "%27ixm0a1b2c3d%27" in payload
    # No literal space: the filter rejects it.
    assert " " not in payload


def test_payload_lands_inside_the_string_it_targets():
    payload = _js_url_payload("ixm0a1b2c3d", "'", prefix="1")
    page = _page(payload)
    hit = analyze_marker(page, "%27ixm0a1b2c3d%27")
    # Detection is only meaningful if the payload is recognised at the sink.
    assert hit.context in (
        InjectionContext.JS_STRING_SINGLE,
        InjectionContext.JS_CODE,
    )
