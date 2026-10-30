"""Context detection matrix — HTML5 state machine vs adversarial inputs."""

from intellixss.analysis.context import analyze_marker, detect_context, find_all
from intellixss.models import InjectionContext


def _ctx(html: str, marker: str = "MARK") -> str:
    return analyze_marker(html, marker).context.value


def test_matrix():
    cases = [
        ('<div title="MARK">x</div>', "html_attr_double"),
        ("<div title='MARK'>x</div>", "html_attr_single"),
        ("<div title=MARK>x</div>", "html_attr_unquoted"),
        ('<a href="MARK">x</a>', "html_attr_href"),
        ('<img src="MARK">', "html_attr_href"),
        ('<!-- MARK -->', "html_comment"),
        ("<textarea>MARK</textarea>", "textarea"),
        ("<title>MARK</title>", "title"),
        ("<p>MARK</p>", "html_text"),
        ("<style>.a{content:'MARK'}</style>", "css_value"),
    ]
    for html, want in cases:
        assert _ctx(html) == want, f"{html} -> {_ctx(html)} (want {want})"


def test_script_strings():
    assert _ctx('<script>var q = "MARK";</script>') == "js_string_double"
    assert _ctx("<script>var q = 'MARK';</script>") == "js_string_single"
    assert _ctx("<script>var q = `MARK`;</script>") == "js_template"
    assert _ctx("<script>alert(MARK)</script>") == "js_code"


def test_escaped_quote_does_not_close_string():
    html = '<script>var s = "a\\"MARK";</script>'
    assert _ctx(html) == "js_string_double"


def test_string_closed_before_marker_is_code():
    html = '<script>var s = "closed"; var t = MARK;</script>'
    assert _ctx(html) == "js_code"


def test_regex_literal_does_not_confuse_quotes():
    html = "<script>var r = /['\"]/; var q = \"MARK\";</script>"
    assert _ctx(html) == "js_string_double"


def test_line_comment_ignores_quotes():
    html = '<script>// it\'s " open\nvar q = "MARK";</script>'
    assert _ctx(html) == "js_string_double"


def test_block_comment_inside_script():
    html = '<script>/* " unbalanced */ var q = "MARK";</script>'
    assert _ctx(html) == "js_string_double"


def test_event_handler_js_string():
    html = '<img src=x onload="startTimer(\'MARK\')">'
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.JS_IN_ATTR
    assert hit.js_string_quote == "'"
    assert hit.attr_name == "onload"


def test_event_handler_code():
    html = '<svg onload="MARK">'
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.JS_IN_ATTR
    assert hit.js_string_quote == ""
    assert hit.quote_char == '"'


def test_event_handler_code_unquoted_attribute():
    """A handler attribute with no quotes is the most exploitable form: the
    value ends at whitespace, so the reflection is raw JS code."""
    html = "<img src=x onload=MARK>"
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.HTML_ATTR_UNQUOTED
    assert hit.js_string_quote == ""
    assert hit.attr_name == "onload"
    assert hit.quote_char == ""


def test_attribute_js_string_quote_char_is_the_html_quote():
    """quote_char is the HTML attribute delimiter, not the JS string quote:
    it drives the attribute breakout, so it must stay '\"' here."""
    html = "<img src=x onload=\"startTimer('MARK')\">"
    hit = analyze_marker(html, "MARK")
    assert hit.js_string_quote == "'"
    assert hit.quote_char == '"'


def test_string_inside_script_not_confused_by_attribute_quotes():
    html = '<script>var a = "x"; var b = \'MARK\';</script>'
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.JS_STRING_SINGLE


def test_tag_between_attributes():
    html = '<div class=a data-y="z" MARK >'
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.HTML_ATTR_UNQUOTED
    assert hit.tag_name == "div"


def test_comment_containing_tags():
    html = "<!-- <div title='x'> --><p>MARK</p>"
    assert _ctx(html) == "html_text"


def test_cdata_skipped():
    html = "<![CDATA[ <div title='x'> ]]><p>MARK</p>"
    assert _ctx(html) == "html_text"


def test_multiline_attribute():
    html = '<div\n  class="x"\n  title="MARK"\n>'
    hit = analyze_marker(html, "MARK")
    assert hit.context == InjectionContext.HTML_ATTR_DOUBLE
    assert hit.attr_name == "title"


def test_best_occurrence_wins():
    """Same marker echoed in text and JS — the JS one is reported."""
    html = '<p>MARK</p><script>var q = "MARK";</script>'
    assert _ctx(html) == "js_string_double"


def test_unknown_without_marker():
    assert detect_context("<html>hi</html>", "NOPE") == InjectionContext.UNKNOWN


def test_find_all_case_insensitive():
    hits = find_all("abcABCabc", "ABC", case_insensitive=True)
    assert len(hits) == 3
