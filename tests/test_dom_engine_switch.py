"""Which engine answers, and why.

``analyze_dom_flows`` is the single entry point the orchestrator calls. Before
this switch it was the regex analyser outright; now the parse tree contributes
first and the regex analyser is consulted as well, because the tree does not
model every source yet.

The rule is stated once, here, and each test pins one clause of it:

1. A flow the tree engine proves is reported. That is what gives the engine its
   precision on the cases the regex analyser cannot do.
2. A flow only the regex analyser sees is *also* reported. Dropping it on a
   clean parse would silently delete every jQuery-parameter and bundle flow,
   which is the regression a parallel run exists to catch.
3. When a page carries both, the tree flow is reported; a parameter flow that
   shares a sink with a hash flow is still lost to the regex engine's window,
   which is recorded as a known limitation rather than asserted away.
4. Without a grammar, the answer is byte-for-byte the regex answer.

Clause 1 and clause 2 pull in opposite directions on a page where the regex
analyser is *wrong*: ``const hash = 1`` produces a flow in regex and none in the
tree. That conflict is not resolved by preference — it is recorded as such, and
the sink-level filter that resolves it lives in the caller.
"""

from intellixss.analysis import static_dom


def test_a_flow_only_the_tree_engine_sees_is_reported():
    js = "fetch(u).then(r => r.text()).then(t => { el.innerHTML = t; });"
    flows = static_dom.analyze_dom_flows(js, [])
    assert any(f[1] == "innerHTML" for f in flows), flows


def test_a_real_flow_is_still_reported():
    js = "el.innerHTML = location.hash;"
    assert ("location.hash", "innerHTML", "html") in static_dom.analyze_dom_flows(js, [])


def test_a_source_the_tree_engine_does_not_model_keeps_the_regex_answer():
    """``$.getParameter`` reaches the sink via an alias the tree has no rule for.

    The tree engine parses this file successfully and reports nothing; the
    regex analyser reports the flow. A successful parse alone must not delete
    the regex answer, or every helper-based page loses its finding.
    """
    js = (
        "var who = $.getParameter('name');\n"
        "document.getElementById('greet').innerHTML = who;"
    )
    flows = static_dom.analyze_dom_flows(js, [])
    assert any(f[0] == "URL parameter" for f in flows), flows


def test_without_a_grammar_the_regex_answer_is_returned_unchanged(monkeypatch):
    """A host where tree-sitter is missing must behave exactly as before."""
    js = "el.innerHTML = location.hash;"
    before = static_dom.analyze_dom_flows(js, [])
    monkeypatch.setattr(static_dom, "_tree_flows", lambda scripts: None)
    after = static_dom.analyze_dom_flows(js, [])
    assert after == before


def test_a_page_with_both_kinds_reports_the_tree_flow():
    """What the union guarantees on a page that has both, and what it does not.

    The regex analyser emits at most one flow per sink text: at the second
    ``innerHTML`` its window also contains ``location.hash``, so it reports the
    hash and never the parameter, even though both reach the sink. The tree
    engine knows there is a hash flow. The parameter flow is therefore still
    lost on *this* page shape — a real limitation of the regex window, recorded
    here rather than papered over by a passing assertion.
    """
    js = (
        "el.innerHTML = location.hash;\n"
        "var who = $.getParameter('name');\n"
        "document.getElementById('greet').innerHTML = who;"
    )
    flows = static_dom.analyze_dom_flows(js, [])
    assert ('location.hash', 'innerHTML', 'html') in flows, flows


def test_a_parameter_only_page_keeps_its_parameter_flow():
    js = (
        "var who = $.getParameter('name');\n"
        "document.getElementById('greet').innerHTML = who;"
    )
    flows = static_dom.analyze_dom_flows(js, [])
    assert ('URL parameter', 'innerHTML', 'html') in flows, flows


def test_the_shadowing_conflict_is_visible_rather_than_hidden():
    """Both engines run, so the regex false positive is still in the union.

    This test documents the cost of clause 2 instead of fixing it here: the
    tree engine proves there is no flow, the regex engine insists there is.
    The caller decides; this function reports what both found.
    """
    js = (
        "function f(){ const hash = 1; "
        "var out = document.getElementById('o'); out.innerHTML = hash; }"
    )
    assert static_dom._tree_flows([js]) == []
    assert any(f[1] == "innerHTML" for f in static_dom.analyze_dom_flows(js, []))
