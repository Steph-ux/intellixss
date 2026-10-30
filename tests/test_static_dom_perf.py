"""Regression: analyze_dom_flows must stay fast on a minified bundle.

The jquery-href lab shipped a 93 KB bundle that made the fixed-point loop
recompute the full taint set per statement (quadratic). That cost 171 s per
call and blew the per-page budget, so the lab was reported CLEAN on timeout.
"""

import time

from intellixss.analysis.static_dom import analyze_dom_flows


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
