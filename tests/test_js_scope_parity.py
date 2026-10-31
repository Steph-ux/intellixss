"""The parallel run: the parse-tree engine against the regex engine.

The regex analyser is not replaced; it is kept as the reference and compared
case by case. Every case below states which answer is *correct* and why, so a
disagreement is a verdict rather than a preference — the new engine may only
differ where it is right.

Two directions are checked separately:

* **False positive the regex engine reports and the tree engine drops.**
  A local ``hash`` is not ``location.hash``; a parameter shadows the global of
  the same name; a computed property names no sink. Reporting a confirmation
  for these is what made the old engine look better than it was.
* **Precision the tree engine adds.** Two functions sharing a name are kept as
  two blocks with distinct symbols instead of one body overwriting the other,
  which is a property of the analysis rather than of any particular page.

A case where the two agree is a case that must keep agreeing: that is the
regression guard for the switch-over.
"""

import pytest

from intellixss.analysis.js_scope import resolve_scopes
from intellixss.analysis.static_dom import analyze_dom_flows

# Cases where the regex engine reports a flow that is not there. The tree
# engine must report nothing, and the regex engine's answer is the defect.
REGEX_FALSE_POSITIVES = {
    "local named like the source":
        "function f(){ const hash = 1; var out = document.getElementById('o'); out.innerHTML = hash; }",
    "parameter shadows the global":
        "var user = location.hash;\nfunction f(user){ el.innerHTML = user; }",
    "computed property is not a sink":
        "obj[key] = location.hash; el.innerHTML = obj[key];",
}

# Cases both engines must keep reporting, so a switch cannot lose them. The
# request-callback case belongs here: the regex engine reaches it through its
# ``.getParameter(`` source, and the tree engine reaches it through the promise
# chain, so they agree on the verdict by different means.
AGREEMENT = {
    "direct source at the sink": "el.innerHTML = location.hash;",
    "single hop alias": "const input = location.hash; el.innerHTML = input;",
    "destructuring from location": "const { hash } = location;\nel.innerHTML = hash;",
    "template literal": "const html = `<b>${location.hash}</b>`;\nel.innerHTML = html;",
    "closure over an outer variable":
        "function outer(){\n  const t = location.hash;\n  return function(){ el.innerHTML = t; };\n}",
    "request callback parameter":
        "fetch(u).then(r => r.text()).then(t => { el.innerHTML = t; });",
    "transform function":
        "function decode(v){ return JSON.parse(atob(v)); }\n"
        "const payload = decode(location.hash.slice(1));\nel.innerHTML = payload;",
}


def _tree(js: str):
    return [
        (w.source, w.sink, w.family)
        for b in resolve_scopes([js])
        for w in b.tainted_writes
    ]


def _regex(js: str):
    return list(analyze_dom_flows(js, []))


@pytest.mark.parametrize("name,js", REGEX_FALSE_POSITIVES.items())
def test_the_tree_engine_drops_a_flow_the_regex_engine_invented(name, js):
    assert _regex(js), f"{name}: the regex engine was expected to report a flow"
    assert _tree(js) == [], f"{name}: the tree engine invented a flow"


@pytest.mark.parametrize("name,js", AGREEMENT.items())
def test_both_engines_agree_on_a_real_flow(name, js):
    assert _tree(js), f"{name}: the tree engine lost a real flow"
    assert _regex(js), f"{name}: the regex engine lost a real flow"


def test_two_functions_sharing_a_name_stay_two_symbols():
    """The regex engine keys functions by name, so one body erases the other.

    The verdict on this snippet is "no flow": neither body reads a source. What
    the tree engine adds is that the two ``render`` definitions survive as
    separate blocks with separate symbols, so the second can no longer erase
    the first when a source is involved.
    """
    js = "function render(x){ el.innerHTML = x; }\nfunction render(y){ el.textContent = y; }"
    renders = [b for b in resolve_scopes([js]) if b.name == "render"]
    assert len(renders) == 2, [b.name for b in resolve_scopes([js])]
    assert renders[0].symbol != renders[1].symbol
