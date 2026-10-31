"""Angular's sanitiser is opt-out: ``bypassSecurityTrustHtml`` is the opt-out.

A ``[innerHTML]`` binding is inert with Angular's sanitiser and executable
without it, so the call that waives the sanitiser is the sink. The regex engine
has modelled it; the tree engine did not, so a component bundle whose only sink
is that call reported no flow at all.
"""

import sys

sys.path.insert(0, r"D:\Steph\File\Projet\kali-tools\xss")

from intellixss.analysis.js_scope import resolve_scopes


def _flows(src: str):
    blocks = resolve_scopes([src])
    return {(w.source, w.sink) for b in blocks for w in b.tainted_writes}


def test_a_trusted_html_template_carrying_a_stored_value_is_a_sink():
    src = """
    class S {
      lastIp;
      parse() {
        let t = {};
        let i = localStorage.getItem("token");
        i && (t = decode(i), t.data.lastLoginIp && (this.lastIp =
          this.sanitizer.bypassSecurityTrustHtml(`<small>${t.data.lastLoginIp}</small>`)));
      }
    }
    """
    assert ("localStorage", "innerHTML") in _flows(src)


def test_a_trusted_html_template_is_a_sink_through_a_local():
    src = """
    function render() {
      const v = localStorage.getItem("token");
      const html = `<small>${v}</small>`;
      el.sanitizer.bypassSecurityTrustHtml(html);
    }
    """
    assert ("localStorage", "innerHTML") in _flows(src)


def test_a_trusted_html_template_with_constant_text_is_not_a_flow():
    src = """
    function render() {
      el.sanitizer.bypassSecurityTrustHtml(`<b>static</b>`);
    }
    """
    assert _flows(src) == set()
