"""Reflection helpers + negative false-positive guards."""

from pathlib import Path

from intellixss.analysis.reflection import find_reflection, is_payload_effective, reflection_score
from intellixss.verify.check import evaluate_response
from intellixss.models import InjectionContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_raw_reflection_score():
    payload = "<img src=x onerror=alert(1)>"
    body = f"<div>out {payload} end</div>"
    assert reflection_score(body, payload) == 1.0
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert ok
    assert "executable" in tag or "raw" in tag


def test_encoded_score_lower():
    payload = "<script>alert(1)</script>"
    body = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
    score = reflection_score(body, payload)
    assert 0 < score < 1


def test_fully_escaped_payload_is_not_executable():
    """An escaped reflection must never be re-interpreted as live markup.

    ``&lt;img src=x onerror=…&gt;`` is shown as text by the browser; decoding
    the whole response first would rebuild the tag the server refused to emit.
    """
    payload = "<img src=x onerror=alert('ixm537f8adc')>"
    body = "<p>&lt;img src=x onerror=alert(&apos;ixm537f8adc&apos;)&gt;</p>"
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert not ok, tag


def test_escaped_echo_next_to_page_own_img_is_not_executable():
    """The page's own tag must not vouch for an escaped echo.

    A layout carrying ``<img class=avatar>`` would make a name-only match
    succeed for ``<img src=x onerror=…>`` even when the reflection is escaped.
    """
    payload = "<img src=x onerror=alert('ixme7626d21')>"
    body = (
        '<header><img src="/resources/images/avatarDefault.svg" class="avatar"></header>'
        "<p>&lt;img src=x onerror=alert(&apos;ixme7626d21&apos;)&gt;</p>"
    )
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert not ok, tag


def test_find_reflection_snippet():
    body = "aaaaMARKER999bbbb"
    snip = find_reflection(body, "MARKER999")
    assert snip is not None
    assert "MARKER999" in snip


def test_evaluate_response_finding():
    payload = "<script>alert(1)</script>"
    body = f"<html><body>q={payload}</body></html>"
    out = evaluate_response(
        url="https://lab.example/search?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_TEXT,
    )
    assert out.success
    assert out.finding is not None
    assert out.finding.parameter == "q"
    assert out.finding.payload == payload


def test_evaluate_network_error():
    out = evaluate_response(
        url="https://x",
        param="q",
        method="GET",
        payload="x",
        status=0,
        body="",
        headers={},
        context=InjectionContext.UNKNOWN,
    )
    assert not out.success
    assert out.diagnosis is not None


def test_alert_text_in_html_text_is_not_xss():
    """xss-game style search bounce: text alert is NOT executable HTML XSS."""
    payload = "'-AlErT(1)-'"
    body = (
        "Sorry, no results were found for <b>'-AlErT(1)-'</b>. "
        "<a href='?'>Try again</a>."
    )
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert not ok, tag
    out = evaluate_response(
        url="https://xss-game.appspot.com/level1/frame?query=x",
        param="query",
        method="GET",
        payload=payload,
        status=200,
        body=f"<html><body>{body}</body></html>",
        headers={},
        context=InjectionContext.HTML_TEXT,
    )
    assert not out.success


def test_alert_text_in_unquoted_attribute_is_not_xss():
    """Passive attribute value containing alert-looking text is not a breakout."""
    payload = "'-alert(1)-'"
    body = "<html><body><tag attribute='-alert(1)-'></body></html>"
    ok, tag = is_payload_effective(body, payload, "html_attr_unquoted")
    assert not ok, tag
    out = evaluate_response(
        url="https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_ATTR_UNQUOTED,
    )
    assert not out.success


def test_unquoted_event_handler_is_xss():
    payload = " onmouseover=alert(1) "
    body = "<html><body><tag attribute= onmouseover=alert(1) ></body></html>"
    ok, tag = is_payload_effective(body, payload, "html_attr_unquoted")
    assert ok, tag
    out = evaluate_response(
        url="https://lab.example/?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_ATTR_UNQUOTED,
    )
    assert out.success
    assert out.finding is not None


def test_js_in_attr_breakout_entity_ok():
    """The tail the page appends closes what the payload opened, so the whole
    handler parses and runs."""
    payload = "3');alert(1);'("
    body = (
        '<img src="/static/loading.gif" '
        'onload="startTimer(\'3&#39;);alert(1);\'(&#39;);" />'
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert ok, tag


def test_js_in_attr_raw_quote_breakout_alone_is_not_effective():
    """``startTimer('3');alert(1)//');`` is a syntax error: the handler is
    parsed as one unit, so a comment cannot hide the trailing ``');``."""
    payload = "3');alert(1)//"
    body = (
        '<img src="/static/loading.gif" '
        'onload="startTimer(\'3&#39;);alert(1)//\');" />'
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert not ok, tag


def test_js_in_attr_encoded_markup_breakout_is_not_effective():
    """A handler-value breakout the app HTML-encoded is inert in a browser:
    ``startTimer('1&quot;&gt;&lt;img …')`` never becomes a tag, so unescaping
    the whole page must not be treated as proof."""
    payload = '1"><img src=x onerror=alert(1)>'
    body = (
        '<img src="/static/loading.gif" '
        'onload="startTimer(\'1&quot;&gt;&lt;img src=x onerror=alert(&#39;1&#39;)&gt;\');" />'
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert not ok, tag


def test_js_in_attr_still_detects_real_page_level_markup():
    """When the handler really breaks — both the JS string *and* the attribute
    are closed — the payload sits outside the tag and confirms."""
    payload = "1' onload='alert(1)'><svg/onload=alert(1)>"
    body = (
        '<img src="x.jpg" onload="startTimer('
        "'1' onload='alert(1)'><svg/onload=alert(1)>\">"
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert ok, tag


def test_tag_inside_quoted_attribute_is_not_xss():
    """<svg> as attribute text without quote breakout must not confirm."""
    payload = "<SvG/oNlOaD=aLeRt(1)>"
    body = '<html><body><tag attribute="<SvG/oNlOaD=aLeRt(1)>"></body></html>'
    ok, tag = is_payload_effective(body, payload, "html_attr_double")
    assert not ok, tag
    out = evaluate_response(
        url="https://lab.example/?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_ATTR_DOUBLE,
    )
    assert not out.success


def test_quoted_attr_breakout_is_xss():
    payload = '"><img src=x onerror=alert(1)>'
    body = '<html><body><tag attribute=""><img src=x onerror=alert(1)>"></body></html>'
    ok, tag = is_payload_effective(body, payload, "html_attr_double")
    assert ok, tag


def test_ambient_img_does_not_confirm_svg_payload():
    """
    Page already has <img> and words svg/onload/alert — must NOT confirm
    payload <svg/onload=alert(1)> unless that payload's tag is reflected raw.
    """
    payload = "<svg/onload=alert(1)>"
    body = """
    <html><body>
      <img src="/logo.png" alt="cloud">
      <p>docs mention svg onload alert for developers</p>
    </body></html>
    """
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert not ok, tag
    out = evaluate_response(
        url="https://lab.example/search?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_TEXT,
    )
    assert not out.success
    assert out.finding is None


def test_svg_payload_confirmed_when_tag_family_raw():
    payload = "<svg/onload=alert(1)>"
    body = f'<html><body><div>out {payload} end</div><img src="/logo.png"></body></html>'
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert ok, tag
    out = evaluate_response(
        url="https://lab.example/search?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_TEXT,
    )
    assert out.success and out.finding is not None


def test_ambient_onerror_does_not_confirm_handler_payload():
    """Ambient onerror=fallback must not confirm ' onerror=alert(1) '."""
    payload = " onerror=alert(1) "
    body = """
    <html><body>
      <img src="/x.png" onerror="fallback()">
      <script>window.onerror=function(){}</script>
    </body></html>
    """
    ok, tag = is_payload_effective(body, payload, "html_attr_unquoted")
    assert not ok, tag
    out = evaluate_response(
        url="https://lab.example/?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_ATTR_UNQUOTED,
    )
    assert not out.success
    assert out.finding is None


def test_ambient_img_onerror_alert_text_does_not_confirm_img_payload():
    """
    Logo <img src=… onerror=…> plus word 'alert' must NOT confirm
    <img src=x onerror=alert(1)> without that distinctive binding reflected.
    """
    payload = "<img src=x onerror=alert(1)>"
    body = """
    <html><body>
      <img src="/static/logo.png" onerror="this.style.display='none'">
      <p>docs: use alert dialogs sparingly</p>
    </body></html>
    """
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert not ok, tag
    out = evaluate_response(
        url="https://lab.example/search?q=x",
        param="q",
        method="GET",
        payload=payload,
        status=200,
        body=body,
        headers={},
        context=InjectionContext.HTML_TEXT,
    )
    assert not out.success
    assert out.finding is None


def test_img_onerror_alert_confirmed_when_distinctive_binding_present():
    payload = "<img src=x onerror=alert(1)>"
    body = f"<html><body>{payload}</body></html>"
    ok, tag = is_payload_effective(body, payload, "html_text")
    assert ok, tag
