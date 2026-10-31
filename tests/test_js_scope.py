"""Names are not enough: taint follows symbols, not identifiers.

The regex analyser keys taint by *name* in a flat ``Dict[str, str]``. That is
enough for a minified bundle where every identifier is unique, and wrong for
everything else: a local ``const hash`` is the same key as ``location.hash``,
two ``render()`` bodies overwrite each other, ``const {hash} = location``
declares no name the rule can see, and a closure that reads an outer tainted
variable is invisible because the variable is not referenced at the sink.

These tests pin the block-by-block contract before the engine behind it exists.
Each case is one of the classes the review named.
"""

from intellixss.analysis.js_scope import resolve_scopes

PAGE = "<html><body><script>{}</script></body></html>"


def _scopes(js: str):
    return resolve_scopes([js])


# ---------------------------------------------------------------- shadowing


def test_a_local_named_like_a_source_property_is_not_the_source():
    """``const hash = 1`` shadows nothing, but it is not ``location.hash``."""
    js = "function f(){ const hash = 1; var out = document.getElementById('o'); out.innerHTML = hash; }"
    blocks = _scopes(js)
    # The sink's value resolves to the *local*, which carries no source.
    writes = [w for b in blocks for w in b.tainted_writes]
    assert writes == [], writes


def test_the_source_still_resolves_when_used_through_location():
    js = "var out = document.getElementById('o'); out.innerHTML = location.hash;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes
    assert writes[0].source == "location.hash"


# ---------------------------------------------------------------- scopes


def test_two_functions_with_the_same_name_do_not_overwrite_each_other():
    """A minified bundle renames per module; two ``render`` bodies coexist."""
    js = (
        "function render(x){ el.innerHTML = x; }\n"
        "function render(y){ el.textContent = y; }\n"
    )
    blocks = _scopes(js)
    renders = [b for b in blocks if b.name == "render"]
    assert len(renders) == 2, [b.name for b in blocks]
    # Distinct symbols: same name, different declaration site.
    assert renders[0].symbol != renders[1].symbol


def test_a_parameter_is_its_own_symbol_not_the_outer_variable():
    js = (
        "var user = location.hash;\n"
        "function f(user){ el.innerHTML = user; }\n"
    )
    blocks = _scopes(js)
    fn = [b for b in blocks if b.name == "f"][0]
    # Inside ``f``, ``user`` is the parameter: the outer source does not reach it
    # unless the call site passes it, and there is no call site here.
    assert fn.tainted_writes == []


# ---------------------------------------------------------------- destructuring


def test_destructuring_from_a_source_declares_tainted_names():
    js = "const { hash } = location; el.innerHTML = hash;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes


def test_destructuring_with_rename_and_nested_default():
    js = "const { hash: h, search = '' } = location; el.innerHTML = h;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes


# ---------------------------------------------------------------- aliases


def test_a_single_hop_alias_is_followed():
    js = "const input = location.hash; el.innerHTML = input;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [(w.source, w.sink) for w in writes] == [("location.hash", "innerHTML")]


def test_an_alias_chain_is_followed_to_the_end():
    js = "let a = location.hash; let b = a; let c = b; el.innerHTML = c;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes


# ---------------------------------------------------------------- templates


def test_a_template_literal_interpolates_taint():
    js = "const html = `<b>${location.hash}</b>`; el.innerHTML = html;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes


def test_a_template_with_several_substitutions_keeps_the_tainted_one():
    js = "const html = `<b>${name}</b>${location.search}<i>${n}</i>`; el.innerHTML = html;"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.source for w in writes] == ["location.search"], writes


# ---------------------------------------------------------------- closures


def test_a_closure_reads_a_tainted_outer_variable():
    """The inner function never mentions the source; it closes over it."""
    js = (
        "function outer(){\n"
        "  const t = location.hash;\n"
        "  return function(){ el.innerHTML = t; };\n"
        "}"
    )
    blocks = _scopes(js)
    inner = [b for b in blocks if b.kind == "function_expression"]
    assert inner, [b.kind for b in blocks]
    writes = [w for b in inner for w in b.tainted_writes]
    assert [w.source for w in writes] == ["location.hash"], writes


# ---------------------------------------------------------------- dynamic


def test_a_computed_property_is_not_guessed():
    """``obj[key]`` cannot be resolved statically; it must not be invented."""
    js = "obj[key] = location.hash; el.innerHTML = obj[key];"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    # The write targets a computed member, so which property it set is unknown;
    # the later read is a computed member too. Nothing at the innerHTML node is
    # tainted, because the taint was stored somewhere the analysis cannot name.
    assert writes == [], writes


# ---------------------------------------------------------------- promise


def test_a_promise_chain_carries_taint_into_the_then_callback():
    js = (
        "fetch(u).then(r => r.text()).then(t => { el.innerHTML = t; });"
    )
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.source for w in writes] == ["fetch response"], writes


# ---------------------------------------------------------------- functions


def test_a_transform_function_returning_attacker_data_stays_tainted():
    js = (
        "function decode(v){ return JSON.parse(atob(v)); }\n"
        "const payload = decode(location.hash.slice(1));\n"
        "el.innerHTML = payload;\n"
    )
    blocks = _scopes(js)
    writes = [w for b in blocks for w in b.tainted_writes if b.kind == "program"]
    assert [w.sink for w in writes] == ["innerHTML"], writes


# ---------------------------------------------------------------- hygiene


def test_a_syntax_error_does_not_lose_the_rest_of_the_file():
    """Recovery is the reason for a parser: one bad node is not a dead file."""
    js = "var broken = (;\nconst html = location.hash;\nel.innerHTML = html;\n"
    writes = [w for b in _scopes(js) for w in b.tainted_writes]
    assert [w.sink for w in writes] == ["innerHTML"], writes


def test_no_source_no_flow():
    js = "const a = 1; el.innerHTML = a;"
    assert [w for b in _scopes(js) for w in b.tainted_writes] == []
