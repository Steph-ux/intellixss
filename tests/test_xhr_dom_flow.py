"""A sink reached through an XHR response is still reachable from the URL.

A page can hand the query string to ``XMLHttpRequest`` and eval the response.
The source and the sink then live in different statements, and the body the
executor sees is a *JSON document* that embeds the value in a string — so the
usual payloads are inert even though the page is vulnerable.
"""

from intellixss.analysis.static_dom import (
    _payload_candidates,
    _tainted_vars,
    analyze_dom_flows,
    fragment_dom_finding,
)

SEARCH_JS = (
    "function search(path) {"
    " var xhr = new XMLHttpRequest();"
    " xhr.onreadystatechange = function() {"
    "  if (this.readyState == 4 && this.status == 200) {"
    "   eval('var searchResultsObj = ' + this.responseText);"
    "   displaySearchResults(searchResultsObj);"
    "  }"
    " };"
    " xhr.open('GET', path + window.location.search);"
    " xhr.send();"
    "}"
)


def test_http_methods_are_not_sinks():
    """``xhr.open('GET'`` is a request, not a handler assignment."""
    assert "get" not in _tainted_vars(SEARCH_JS)


def test_response_inherits_the_taint_of_the_requested_url():
    taint = _tainted_vars(SEARCH_JS)
    assert taint.get("responseText") == "location.search"
    assert taint.get("xhr") == "location.search"


def test_eval_of_a_response_is_a_flow():
    flows = analyze_dom_flows("", [SEARCH_JS])
    assert ("location.search", "eval", "code") in flows


def test_json_eval_gets_a_string_breakout_not_bare_code():
    payloads = [p for p, _ in _payload_candidates("code", "eval", SEARCH_JS, "location.search")]
    assert payloads
    # The server escapes the quote, so the payload carries one backslash of its
    # own to close the string inside the eval'd source.
    assert payloads[0].startswith('\\"')
    assert payloads[0].endswith("//")
    # Bare code never leaves the JSON string and would read as "inert".
    assert payloads[0] != "alert(1)"


def test_sink_prefers_code_execution_over_a_markup_family():
    html = (
        "<html><body><script src=\"/search.js\"></script>"
        "<script>var q = location.search;</script></body></html>"
    )
    finding = fragment_dom_finding(
        "https://x.test/?search=1", html, marker="ixm0a1b2c3d", external_js=[SEARCH_JS]
    )
    assert finding is not None
    assert "eval" in finding.evidence


def test_external_body_reaches_the_analyser():
    flows = analyze_dom_flows("<html></html>", [SEARCH_JS])
    assert flows, "an external script body must be analysed like an inline one"
