"""A flattened bundle declares the same name many times.

Webpack and esbuild emit a bundle as one scope in which every module's locals
share a namespace, separated only by an inline guard::

    var a = function (x) { … };
    …
    if (typeof f === "function") return f.call(…);
    …
    var f = function (y) { c.innerHTML = y; };

Lexically this is one binding whose last write wins. Operationally every
definition runs, so analysis by last-write cannot see the sink in ``a`` and
reports the bundle as clean — which is exactly what the Juice Shop's
``main.js`` produced: 1.2 MB, 4943 blocks, 9018 bindings, zero flows.

These tests pin the *distinction* rather than the leniency: a name declared
once in an inner scope still shadows and still suppresses the write, while a
name declared repeatedly at the top of a file keeps every definition.
"""

from intellixss.analysis.js_scope import resolve_scopes


def _writes(js: str):
    return [w for b in resolve_scopes([js]) for w in b.tainted_writes]


def test_a_name_declared_once_does_not_suppress_its_own_flow():
    js = "var a = function (c) { c.innerHTML = location.hash; };"
    assert [w.source for w in _writes(js)] == ["location.hash"], _writes(js)


def test_a_bundle_style_redeclaration_keeps_the_earlier_sink():
    """The sink lives in the first definition, the source in a later one."""
    js = (
        "var a = function (c) { c.innerHTML = location.hash; };\n"
        "if (typeof f === 'function') { a(1); }\n"
        "var a = function (c) { c.textContent = c; };"
    )
    writes = _writes(js)
    assert any(w.sink == "innerHTML" for w in writes), writes


def test_a_shadowing_inner_declaration_still_suppresses():
    """Precision is not traded away: an inner declaration is still a shadow."""
    js = (
        "var html = 1;\n"
        "function render(){ var html = 2; el.innerHTML = html; }"
    )
    assert _writes(js) == [], _writes(js)


def test_two_functions_sharing_a_name_remain_two_blocks():
    js = "function render(x){ el.innerHTML = x; }\nfunction render(y){ el.innerHTML = y; }"
    renders = [b for b in resolve_scopes([js]) if b.name == "render"]
    assert len(renders) == 2


def test_a_redeclared_name_is_marked_multi_defined():
    js = (
        "var a = function (c) { c.innerHTML = location.hash; };\n"
        "var a = function (c) { c.textContent = c; };"
    )
    program = resolve_scopes([js])[0]
    b = program.binding("a")
    assert b is not None
    assert b.kind == "multi", b.kind
