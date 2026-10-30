"""Regression: analyze_dom_flows must stay fast on a minified bundle.

The jquery-href lab shipped a 93 KB bundle that made the fixed-point loop
recompute the full taint set per statement (quadratic). That cost 171 s per
call and blew the per-page budget, so the lab was reported CLEAN on timeout.
"""

import time

from intellixss.analysis.static_dom import _tainted_vars, analyze_dom_flows


def test_minified_bundle_is_fast():
    # A bundle shaped like the one that triggered the blow-up: a large tainted
    # minified blob plus many locals built from it.
    blob = "var a=" + "".join(f"f{i}(location.search);" for i in range(4000))
    html = (
        "<html><body><script src='/bundle.js'></script>"
        "<script>var h='<b>'+location.search+'</b>';el.innerHTML=h;</script>"
        "</body></html>"
    )
    started = time.monotonic()
    flows = analyze_dom_flows(html, [blob])
    elapsed = time.monotonic() - started
    assert elapsed < 10.0, f"analyze_dom_flows took {elapsed:.1f}s on {len(blob)} bytes"
    assert any(f[0] == "location.search" for f in flows)


def test_argument_list_starts_after_the_opening_paren():
    """``_split_args`` is given the ``(`` itself, not the byte after it.

    Passing ``m.end()`` made every argument list one character short, so the
    URL of a ``fetch`` was read as ``")"`` and the response never carried the
    taint of the request. A bundle full of correct call sites then produced no
    DOM flow at all.
    """
    js = (
        "fetch('/rest/products/search?q=' + q).then(r => r.json()).then(data => {\n"
        "  var html = '';\n"
        "  data.forEach(p => { html += '<div>' + p.name + '</div>'; });\n"
        "  document.getElementById('out').innerHTML = html;\n"
        "});"
    )
    assert ("URL parameter", "innerHTML", "html") in analyze_dom_flows(js, [])


def test_plain_script_body_is_analysed_without_a_script_wrapper():
    """A caller that already extracted the body must not get an empty scan."""
    js = "var h = location.hash.substr(1); document.write(h);"
    assert ("location.hash", "document.write", "html") in analyze_dom_flows(js, [])


def test_collateral_loops_stay_untainted():
    """Only callbacks bound to a response body are tainted.

    Marking every ``collection.forEach(item => …)`` of a bundle as
    attacker-controlled fills the flow list with DOM mount points that carry
    no user input.
    """
    js = (
        "<script>\nvar items = [1, 2, 3];\n"
        "items.forEach(i => { el.innerHTML = i; });\n</script>"
    )
    assert analyze_dom_flows(js, []) == []


def test_taint_cost_does_not_scale_with_the_number_of_declarations():
    """The assignment rule indexes statements once and tests by substring.

    The earlier form recompiled a word-boundary pattern per (name, statement)
    pair — 53 million compiles on Juice Shop's 1.3 MB bundle, 355 s for one
    call. A bundle with thousands of unrelated declarations still resolves
    the chain in constant time per name.
    """
    filler = "\n".join(f"var k{i} = 'v{i}' + (i * {i});" for i in range(4000))
    js = (
        filler
        + "\nvar q = new URLSearchParams(location.search).get('q');\n"
        + "var html = '';\n"
        + "html += '<b>' + q + '</b>';\n"
        + "document.getElementById('o').innerHTML = html;\n"
    )
    started = time.monotonic()
    tainted = _tainted_vars(js)
    elapsed = time.monotonic() - started
    assert tainted.get("html") == "location.search"
    assert elapsed < 10.0, f"taint resolution took {elapsed:.1f}s on 4000 declarations"
