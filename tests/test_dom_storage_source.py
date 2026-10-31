"""DOM sinks fed by a client-side store rather than by the URL.

A page that decodes a value out of ``localStorage`` into ``innerHTML`` is a DOM
sink with a browser-owned source, exactly like ``window.name``: nothing in the
URL reaches it. The finding therefore has to carry a seed the confirmer plants
in storage before the page's first script runs — after ``goto()`` is too late,
because an SPA router reads its token synchronously and renders nothing when it
is missing.
"""

from intellixss.analysis.static_dom import (
    analyze_dom_flows,
    dom_source_finding,
    source_seed,
)

TOKEN_SINK = """
<html><body><div id="out"></div><script>
var token = localStorage.getItem('token');
var payload = JSON.parse(atob(token.split('.')[1])).data.ip;
document.getElementById('out').innerHTML = '<small>' + payload + '</small>';
</script></body></html>
"""


def test_storage_flow_is_detected():
    flows = analyze_dom_flows(TOKEN_SINK)
    assert any(f[0] == "localStorage" for f in flows), flows


def test_storage_sink_yields_a_finding_with_a_storage_seed():
    f = dom_source_finding("http://x.test/#/last-login-ip", TOKEN_SINK, marker="ixm1234abcd")
    assert f is not None
    assert f.parameter == "localStorage"
    assert "storage" in f.seeds
    assert "token" in f.seeds["storage"]
    # The marker rides inside the encoded claim, which is where the page reads it.
    part = f.seeds["storage"]["token"].split(".")[1]
    part += "=" * (-len(part) % 4)
    import base64
    import json

    claims = json.loads(base64.urlsafe_b64decode(part))
    assert "ixm1234abcd" in claims["data"]["lastLoginIp"]


def test_storage_seed_is_a_decodable_token_carrying_the_payload():
    """The page decodes the stored value; a bare payload throws before rendering."""
    import base64
    import json

    seed = source_seed("localStorage", "<img src=x onerror=alert('IXM1')>", "http://x.test/")
    token = seed["storage"]["token"]
    assert token.count(".") == 2, token
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    claims = json.loads(base64.urlsafe_b64decode(part))
    assert claims["data"]["lastLoginIp"] == "<img src=x onerror=alert('IXM1')>"


def test_storage_seed_key_follows_the_source_read():
    """The seed must land under the key the page actually reads."""
    seed = source_seed("localStorage", "<img src=x>", "http://x.test/")
    assert set(seed) == {"storage"}
    assert set(seed["storage"]) == {"token"}


def test_storage_lookup_seed_covers_item_and_property_forms():
    seed = source_seed("localStorage.getItem(token)", "ALERT", "http://x.test/")
    assert "token" in seed["storage"]


def test_session_storage_uses_its_own_seed_name():
    seed = source_seed("sessionStorage", "ALERT", "http://x.test/")
    assert set(seed) == {"session_storage"}


COMPONENT_BUNDLE = (
    "var Ag=(()=>{class e{sanitizer=p$1(em);lastLoginIp=`?`;parseAuthToken(){let t={},"
    "i=localStorage.getItem(`token`);i&&(t=d$1(i),t.data.lastLoginIp&&(this.lastLoginIp="
    "this.sanitizer.bypassSecurityTrustHtml(`<small>${t.data.lastLoginIp}</small>`))))}"
    "return e})();"
)


def test_sink_in_an_external_bundle_is_found():
    """An SPA shell names the sink nowhere; it ships it in a ``<script src>``."""
    shell = "<html><body><app-root></app-root><script src='/main.js'></script></body></html>"
    assert dom_source_finding("http://x.test/", shell, marker="ixm1234abcd") is None
    f = dom_source_finding(
        "http://x.test/", shell, marker="ixm1234abcd", external_js=[COMPONENT_BUNDLE]
    )
    assert f is not None
    assert f.parameter == "localStorage"


def test_trusted_html_sink_gets_bare_markup_not_a_quote_breakout():
    """``bypassSecurityTrustHtml`` inserts the value as markup, not in an attribute."""
    shell = "<html><body><script src='/main.js'></script></body></html>"
    f = dom_source_finding(
        "http://x.test/", shell, marker="ixm1234abcd", external_js=[COMPONENT_BUNDLE]
    )
    assert f is not None
    assert f.payload.startswith("<img src=x onerror="), f.payload
    assert not f.payload.startswith("'>"), f.payload
