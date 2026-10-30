"""DOM source analysis: property assignment must not crash taint tracking."""

from intellixss.analysis.static_dom import (
    analyze_dom_flows,
    dom_source_finding,
    source_seed,
)

# The shape that used to crash: a source assigned to a property, not a local.
PROPERTY_ASSIGN = """
<html><body><script>
function lookup(name) { return null; }
var payload = lookup('badValue');
function trigger(p) { eval(p); };
setTimeout(function() { trigger(lookup('badValue')); }, 10);
</script></body></html>
"""

WINDOW_NAME = """
<html><body><script>
if (window.name == "") { window.name = "x"; }
var payload = window.name;
eval(payload);
</script></body></html>
"""

REFERRER = """
<html><body><script>
var payload = document.referrer;
function trigger(p) { eval(p); }
eval(payload);
</script></body></html>
"""


def test_property_assignment_does_not_crash_taint_analysis():
    flows = analyze_dom_flows(PROPERTY_ASSIGN)
    assert isinstance(flows, list)


def test_window_name_flow_is_detected():
    flows = analyze_dom_flows(WINDOW_NAME)
    assert any(f[0] == "window.name" for f in flows), flows


def test_referrer_flow_is_detected():
    flows = analyze_dom_flows(REFERRER)
    assert any(f[0] == "document.referrer" for f in flows), flows


def test_source_finding_carries_a_browser_seed():
    f = dom_source_finding("http://x.test/p", WINDOW_NAME, marker="ixm1234abcd")
    assert f is not None
    assert f.parameter == "window.name"
    assert "window_name" in f.seeds
    assert "ixm1234abcd" in f.seeds["window_name"]


def test_referrer_seed_carries_the_payload_verbatim():
    """The seed is installed as ``document.referrer`` before page scripts run.

    It is deliberately *not* re-encoded: the sink decides what to do with it
    (this family applies ``unescape()`` itself), and double-encoding would turn
    a percentage-encoded call back into a syntax error.
    """
    f = dom_source_finding("http://x.test/p", REFERRER, marker="ixm1234abcd")
    assert f is not None
    assert f.seeds["referrer"] == f.payload


def test_source_seed_rejects_url_driven_sources():
    assert source_seed("location.hash", "alert(1)", "http://x.test/") == {}


def test_hash_only_page_yields_no_source_finding():
    """Fragment sources belong to fragment analysis, not this one."""
    html = "<html><body><script>eval(location.hash.slice(1))</script></body></html>"
    assert dom_source_finding("http://x.test/p#a", html, marker="ixm1234abcd") is None
