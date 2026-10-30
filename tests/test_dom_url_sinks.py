"""DOM URL sinks, Angular template detection, source seeding, marker purity."""

from intellixss.analysis.static_dom import (
    _mark_payload,
    _payload_candidates,
    analyze_dom_flows,
    angular_template_finding,
    dom_source_finding,
    fragment_dom_finding,
    source_seed,
)

# --- URL-followed sinks -------------------------------------------------

IFRAME_SRC = """
<html><body><script>
var payload = document.location.hash.substr(1);
var iframe = document.createElement("iframe");
iframe.src = payload;
document.body.appendChild(iframe);
</script></body></html>
"""

FORM_ACTION = """
<html><body><script>
var payload = document.location.hash.substr(1);
var f = document.createElement("form");
f.action = payload;
document.body.appendChild(f);
</script></body></html>
"""

DOC_LOCATION = """
<html><body><script>
var payload = document.location.hash.substr(1);
document.location = payload;
</script></body></html>
"""

SCRIPT_SRC = """
<html><body><script>
var payload = document.location.hash.substr(1);
var s = document.createElement("script");
s.src = "/static/" + payload;
document.body.appendChild(s);
</script></body></html>
"""


def test_iframe_src_is_recognised_as_a_src_sink():
    sinks = {s for _, s, _ in analyze_dom_flows(IFRAME_SRC)}
    assert "frame_src" in sinks, sinks


def test_form_action_is_recognised_as_a_src_sink():
    sinks = {s for _, s, _ in analyze_dom_flows(FORM_ACTION)}
    assert "form_action" in sinks, sinks


def test_url_followed_sinks_get_a_javascript_payload():
    for sink in ("frame_src", "form_action", "location.assign"):
        payload, _ = _payload_candidates("src", sink)[0]
        assert payload.startswith("javascript:"), (sink, payload)


def test_frame_src_is_preferred_over_generic_src_when_both_are_tainted():
    """A page tainting both ``.src`` and ``iframe.src`` must advertise the sink
    the browser can actually follow, not the inert markup reassembly."""
    f = fragment_dom_finding("http://x.test/p", IFRAME_SRC, marker="ixm1234abcd")
    assert f is not None
    assert f.payload.startswith("javascript:"), f.payload


def test_document_location_assignment_yields_a_javascript_payload():
    f = fragment_dom_finding("http://x.test/p", DOC_LOCATION, marker="ixm1234abcd")
    assert f is not None
    assert f.payload.startswith("javascript:"), f.payload


def test_dynamically_created_script_gets_a_script_url():
    """A fragment that becomes a new ``<script>.src`` is a gadget: the payload
    must be a script URL (no attacker host needed), never inert markup."""
    f = fragment_dom_finding("http://x.test/p", SCRIPT_SRC, marker="ixm1234abcd")
    assert f is not None
    assert f.payload.startswith(("data:text/javascript", "//")), f.payload


# --- marker purity ------------------------------------------------------


def test_marker_is_not_doubly_quoted():
    """The marker must land inside exactly one level of quoting."""
    out = _mark_payload("alert(1)", "ixm1234abcd")
    assert out == "alert('ixm1234abcd')", out


def test_marker_is_not_reapplied():
    already = "alert('ixm1234abcd')"
    assert _mark_payload(already, "ixm1234abcd") == already


def test_marker_survives_a_backtick_context():
    out = _mark_payload("constructor(`alert(1)`)()", "ixm1234abcd")
    assert out == "constructor(`alert('ixm1234abcd')`)()", out


# --- Angular ------------------------------------------------------------

ANGULAR = """
<html ng-app>
  <body>
    <script src="//ajax.googleapis.com/ajax/libs/angularjs/1.4.0/angular.js"></script>
    <div>{{x}}</div>
  </body>
</html>
"""

ANGULAR_NO_APP = """
<html>
  <body>
    <script src="//ajax.googleapis.com/ajax/libs/angularjs/1.4.0/angular.js"></script>
    <div>{{x}}</div>
  </body>
</html>
"""

ANGULAR_NO_LOADER = """
<html ng-app><body><div>{{x}}</div></body></html>
"""


def test_angular_template_injection_is_detected():
    f = angular_template_finding("http://x.test/p", ANGULAR, marker="ixm1234abcd")
    assert f is not None
    assert "{{" in f.payload


def test_angular_finding_is_static_not_confirmed():
    f = angular_template_finding("http://x.test/p", ANGULAR, marker="ixm1234abcd")
    assert f is not None
    assert f.browser_confirmed is False


def test_angular_root_is_not_spelled_ng_app_only():
    """A compiler script plus a template compiles with no ``ng-app`` anywhere.

    That is the whole point of the fix: the old rule was false-negative on every
    app bootstrapped from script, which is most of them.
    """
    html = """
    <html><body>
      <script src="//ajax.googleapis.com/ajax/libs/angularjs/1.4.0/angular.js"></script>
      <div ng-controller="c">{{x}}</div>
    </body></html>
    """
    assert angular_template_finding("http://x.test/p", html, marker="ixm1") is not None


def test_angular_without_a_root_or_a_template_is_not_injectable():
    assert angular_template_finding("http://x.test/p", ANGULAR_NO_APP, marker="ixm1") is None


def test_angular_requires_a_compiler_script():
    assert angular_template_finding("http://x.test/p", ANGULAR_NO_LOADER, marker="ixm1") is None


def test_angular_payloads_carry_the_marker_once():
    f = angular_template_finding("http://x.test/p", ANGULAR, marker="ixm1234abcd")
    assert f is not None
    for p in f.payload_candidates:
        assert p.count("ixm1234abcd") == 1, p


# --- source seeds -------------------------------------------------------


def test_cookie_source_is_seeded_under_the_page_cookie_name():
    html = """
    <html><body><script>
    var payload = lookupCookie('badValue');
    eval(payload);
    </script></body></html>
    """
    seeds = source_seed("document.cookie", "alert(1)", "http://x.test/p")
    assert seeds["cookies"][0][0] == "badValue"


def test_window_name_seed_is_the_payload_itself():
    seeds = source_seed("window.name", "alert('ixm1234abcd')", "http://x.test/p")
    assert seeds == {"window_name": "alert('ixm1234abcd')"}


def test_url_sources_need_no_seed():
    for src in ("location.hash", "location.search", "location.href"):
        assert source_seed(src, "alert(1)", "http://x.test/p") == {}
