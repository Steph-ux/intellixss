"""DOM XSS: source→sink flow analysis (static + browser replay)."""

from intellixss.analysis.static_dom import (
    analyze_dom_flows,
    analyze_dom_sources_sinks,
    fragment_dom_finding,
)

LEVEL2_HTML = """
<script>
  var defaultMessage = "Welcome!<br><br>This is your <i>personal</i> stream.";
  var DB = new PostDB(defaultMessage);
  function displayPosts() {
    var containerEl = document.getElementById("post-container");
    containerEl.innerHTML = "";
    var posts = DB.getPosts();
    for (var i=0; i<posts.length; i++) {
      var html = '<table class="message"><tr><td valign=top>'
        + '<img src="/static/level2_icon.png"> </td> <td valign=top '
        + ' class="message-container"> <div class="shim"></div>';
      html += '<b>You</b>';
      html += '<div class="post">' + posts[i].message + '</div>';
      html += '</table>';
      containerEl.innerHTML += html;
    }
  }
</script>
"""

LEVEL3_HTML = """
<script>
  var num = location.hash.substr(1);
  $('#tabContent').html("<img src='/static/level3/cloud" + num + ".jpg' />");
</script>
"""

LEVEL6_SRC_HTML = """
<script>
  function includeGadget(url) {
    var scriptEl = document.createElement('script');
    if (url.match(/^https?:\\/\\//)) { return; }
    scriptEl.src = url;
    document.head.appendChild(scriptEl);
  }
  function getGadgetName() { return window.location.hash.substr(1) || "/static/gadget.js"; }
  includeGadget(getGadgetName());
</script>
"""


def test_hash_to_jquery_html_pair():
    pairs = analyze_dom_sources_sinks(LEVEL3_HTML)
    assert ("location.hash", "jquery.html") in pairs


def test_level3_finding_is_attribute_breakout():
    finding = fragment_dom_finding("https://lab/level3/frame", LEVEL3_HTML)
    assert finding is not None
    assert finding.vulnerability_type == "dom"
    assert "onerror" in finding.payload
    assert "jquery.html" in finding.evidence


def test_level6_script_src_flow_is_detected():
    flows = analyze_dom_flows(LEVEL6_SRC_HTML)
    # window.location.hash flows into script.src via getGadgetName()
    assert any(f[2] == "src" for f in flows), flows


def test_level6_payload_is_a_script_url_not_markup():
    """A gadget loader takes a script URL: the fragment is URI-decoded by the
    browser, so ``</script>`` can never break out — the payload must be code
    the loader can fetch, and a data: URI keeps it self-contained."""
    finding = fragment_dom_finding("https://lab/level6/frame", LEVEL6_SRC_HTML)
    assert finding is not None
    assert finding.payload.startswith("data:text/javascript,"), finding.payload
    assert "</script>" not in finding.payload
    # A fallback for pages that only accept http(s) gadgets is kept in order.
    assert any(c.startswith("//") for c in finding.payload_candidates), finding.payload_candidates


def test_no_finding_without_source_to_sink_flow():
    # source present but never reaches a sink
    html = "<script>var x = location.hash; console.log(x);</script>"
    assert fragment_dom_finding("https://lab/x", html) is None


def test_no_finding_with_sink_but_no_source():
    assert fragment_dom_finding("https://lab/x", LEVEL2_HTML) is None


def test_level4_entity_encoded_js_breakout_is_rejected():
    """The app emits ``&#39;``, the browser decodes it back to ``'``, and the
    handler becomes ``startTimer('3');alert(1);//');`` — a syntax error, so the
    line never runs. The oracle must not call that executable."""
    from intellixss.analysis.reflection import is_payload_effective

    payload = "3');alert(1);//"
    body = (
        '<img src="/static/loading.gif" '
        'onload="startTimer(\'3&#39;);alert(1);//\');" />'
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert not ok, tag


def test_level4_comma_expression_is_effective():
    """The comma form keeps the surrounding call valid, so it runs beside it."""
    from intellixss.analysis.reflection import is_payload_effective

    payload = "1',alert('ixm1234abcd'),'"
    body = (
        '<img src="/static/loading.gif" '
        'onload="startTimer(\'1&#39;,alert(&#39;ixm1234abcd&#39;),&#39;\');" />'
    )
    ok, tag = is_payload_effective(body, payload, "js_in_attr")
    assert ok, tag
