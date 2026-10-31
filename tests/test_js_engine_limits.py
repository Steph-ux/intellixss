"""What the tree engine does *not* model, written down instead of assumed.

The engine answers on fixtures and reports nothing on the Juice Shop's own
1.2 MB ``main.js``, which the regex analyser scans into a dozen flows. Rather
than call that a defect of either side, the gap is pinned here as a fact so a
future change is measured against it.

The bundle's real shape:

    function h2(c){ if(!(!c||!y)){ var a=M.createElement(`style`);
        a.setAttribute(`type`,`text/css`), a.innerHTML=c; … } }

Three things are true at once, and each would be wrong to fix by guessing:

* ``c`` is a parameter of ``h2`` and nothing in the source text proves where
  its value comes from. The regex analyser reaches the same line through a
  ``.getParameter(`` hit elsewhere in the file, which is a file-wide guess.
* ``a.innerHTML=c`` is a *sequence* inside one ``if``, not a statement of its
  own, so the guard is what makes it a candidate, not the assignment.
* The engine deliberately reports only flows it can prove, so it returns
  nothing here and the union keeps the regex answer.

These tests exist so that "the tree engine finds nothing on a bundle" is a
recorded limitation with a cause, not a surprise discovered during a scan.
"""

from intellixss.analysis.js_scope import resolve_scopes
from intellixss.analysis.static_dom import analyze_dom_flows, _tree_flows


def test_a_parameter_with_no_provable_source_is_not_a_flow():
    js = (
        "function h2(c){ if(!(!c||!y)){ var a=M.createElement(`style`);"
        "a.setAttribute(`type`,`text/css`),a.innerHTML=c; } }"
    )
    assert _tree_flows([js]) == []


def test_the_union_keeps_the_regex_answer_when_the_tree_is_silent():
    """Silence from the tree must never turn a reported page into a clean one."""
    js = (
        "var who = $.getParameter('name');\n"
        "function h2(c){ var a=document.createElement('style');"
        "a.innerHTML=who; }"
    )
    assert _tree_flows([js]) == []
    flows = analyze_dom_flows(js, [])
    assert any(f[1] == "innerHTML" for f in flows), flows


def test_a_sequence_expression_still_reaches_its_sink():
    """``a=b, a.innerHTML=c`` is one statement; the inner sink is still found."""
    js = "function f(){ var a = document.createElement('div'); (a.x = 1, a.innerHTML = location.hash); }"
    writes = [w for b in resolve_scopes([js]) for w in b.tainted_writes]
    assert any(w.sink == "innerHTML" for w in writes), writes
