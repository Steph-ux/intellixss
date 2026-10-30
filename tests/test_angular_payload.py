"""An AngularJS expression is compiled, so the marker must survive its quotes.

Angular evaluates a ``{{…}}`` expression inside an ``ng-app`` subtree. The
expression that reaches ``Function`` is a JS string literal, and the marker has
to sit inside it — nested inside whatever quotes the expression already uses.
Getting that nesting wrong produces a payload that is echoed verbatim by the
page and never runs, which reads as a "clean" result on a vulnerable page.
"""

from intellixss.analysis.static_dom import angular_template_finding, _mark_payload

PAGE = (
    "<html><body ng-app><script src=\"/resources/js/angular_1-7-7.js\"></script>"
    "<h1>0 search results for '{{MARK}}'</h1></body></html>"
)


def test_angular_payload_nests_the_marker_in_the_right_quotes():
    payload = _mark_payload('constructor.constructor(\'alert("1")\')()', "ixm0a1b2c3d")
    assert payload == 'constructor.constructor(\'alert("ixm0a1b2c3d")\')()'


def test_marker_is_not_double_quoted_inside_a_double_quoted_string():
    # Reusing the surrounding quote would terminate the string early.
    payload = _mark_payload('f("alert(1)")', "ixm0a1b2c3d")
    assert '"alert(ixm0a1b2c3d)"' not in payload


def test_finding_targets_the_parameter_that_was_scanned():
    finding = angular_template_finding(
        "https://example.test/?search=x", PAGE, marker="ixm0a1b2c3d", parameter="search"
    )
    assert finding is not None
    assert finding.parameter == "search"


def test_finding_carries_the_marker_through_every_candidate():
    finding = angular_template_finding(
        "https://example.test/?q=x", PAGE, marker="ixm0a1b2c3d", parameter="q"
    )
    assert finding is not None
    for candidate in finding.payload_candidates:
        assert "ixm0a1b2c3d" in candidate, candidate


def test_no_ng_app_means_no_angular_finding():
    assert angular_template_finding("https://x.test/", "<html><body></body></html>") is None
