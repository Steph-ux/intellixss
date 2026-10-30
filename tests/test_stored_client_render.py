"""Stored content served as JSON reaches the DOM through the page's own script.

A comment thread is not in the HTML: the document is a shell and the server
hands the records back as JSON that page script turns into markup. Three things
have to be read off the page rather than assumed — where the records are served
from, how the page escapes them, and which document consumes them.
"""

import json

from intellixss.plugins.stored_xss import (
    _build_payloads,
    _first_occurrence_sanitizer,
    _json_value_context,
    _opens_a_complete_element,
)

ESCAPE_ONCE = (
    "function escapeHTML(html) {"
    " return html.replace('<', '&lt;').replace('>', '&gt;'); }"
)
ESCAPE_ALL = (
    "function escapeHTML(html) {"
    " return html.replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }"
)


def test_single_pass_replace_is_recognised():
    assert _first_occurrence_sanitizer(ESCAPE_ONCE)


def test_global_replace_is_not_treated_as_single_pass():
    assert not _first_occurrence_sanitizer(ESCAPE_ALL)


def test_payload_leading_pair_absorbs_both_replacements():
    payloads = _build_payloads("ixm0a1b2c3d", 3, page_js=ESCAPE_ONCE)
    assert payloads and payloads[0].startswith("<>")
    # Without the observation the leading pair would be wasted syntax.
    plain = _build_payloads("ixm0a1b2c3d", 3, page_js="")
    assert plain and not plain[0].startswith("<>")


def test_leading_pair_survives_the_page_escape():
    """Simulate the page's escaping to prove the element behind it is live."""
    payload = _build_payloads("ixm0a1b2c3d", 1, page_js=ESCAPE_ONCE)[0]
    escaped = payload.replace("<", "&lt;", 1).replace(">", "&gt;", 1)
    assert "<img" in escaped, escaped


def test_json_value_is_extracted_from_the_record():
    body = json.dumps(
        {"comments": [{"author": "a", "body": "<img src=x onerror=alert('ixm1')>"}]}
    )
    assert _json_value_context(body, "ixm1") == "<img src=x onerror=alert('ixm1')>"


def test_json_wrapper_is_not_mistaken_for_markup():
    """The document around the record is not what reaches the parser."""
    body = json.dumps({"body": "plain text ixc0a1b2c3"})
    value = _json_value_context(body, "ixc0a1b2c3")
    assert value == "plain text ixc0a1b2c3"
    assert "{" not in value


def test_non_json_body_yields_no_value():
    assert _json_value_context("<html>ixc1</html>", "ixc1") is None


def test_complete_element_is_recognised():
    assert _opens_a_complete_element("<img src=x onerror=alert('ixm1')>")
    assert _opens_a_complete_element("<><img src=x onerror=alert('ixm1')>")


def test_attribute_fragment_is_not_a_complete_element():
    assert not _opens_a_complete_element("1' onerror=alert('ixm1')")
    assert not _opens_a_complete_element("onerror=alert('ixm1')")
