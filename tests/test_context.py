"""Context detection tests against fixtures."""

from pathlib import Path

from intellixss.analysis.context import detect_context
from intellixss.models import InjectionContext

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str, marker: str = "CANARY_HERE") -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_html_text_context():
    html = _load("html_text_reflect.html")
    assert detect_context(html, "CANARY_HERE") == InjectionContext.HTML_TEXT


def test_attr_double_context():
    html = _load("attr_double.html")
    assert detect_context(html, "CANARY_HERE") == InjectionContext.HTML_ATTR_DOUBLE


def test_js_string_double_context():
    html = _load("js_string.html")
    ctx = detect_context(html, "CANARY_HERE")
    assert ctx in (
        InjectionContext.JS_STRING_DOUBLE,
        InjectionContext.JS_CODE,
        InjectionContext.JS_STRING_SINGLE,
    )


def test_unknown_without_marker():
    assert detect_context("<html>hi</html>", "NOPE") == InjectionContext.UNKNOWN
