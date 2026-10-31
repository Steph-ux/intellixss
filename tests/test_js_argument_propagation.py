"""A function that writes its parameter is a sink once a caller passes taint.

The measure that started this: Juice Shop's `main.js` assigns markup through
`function h2(c){ a.innerHTML = c }` and is called as `h2(location.search)`.
The tree engine reported no flow at all, because the sink's argument is a
parameter and the body alone says nothing about where its value came from.
The regex engine reported roughly twelve flows on the same bundle - by name,
which is why it also reports a `const hash = 1` as a taint flow.

What these tests pin is the propagation that makes the tree engine useful on a
real bundle without giving up its precision:

* a parameter written into a sink is a flow when a call site passes a tainted
  argument to that parameter, and is *not* a flow when every caller passes a
  constant;
* arguments are matched to parameters by position, and a call site that does not
  supply an argument does not taint the parameters it omits;
* a function called with more arguments than it declares is not guessed at;
* a parameter with a default value keeps the caller's taint when one is passed.
"""

from intellixss.analysis.js_scope import resolve_scopes


def _flows(src: str):
    # ``$(…)`` and ``Uc``/``Map`` are page globals the analyser does not model;
    # declaring them keeps the fixture about the join and not about resolution.
    blocks = resolve_scopes([src])
    return [
        (w.sink, w.source)
        for b in blocks
        for w in b.tainted_writes
    ]


def test_a_parameter_written_into_a_sink_is_a_flow_when_a_caller_taints_it():
    src = """
    function h2(c) { a.innerHTML = c; }
    h2(location.search);
    """
    assert ("innerHTML", "location.search") in _flows(src)


def test_a_parameter_whose_callers_are_all_constant_is_not_a_flow():
    """The whole point of the tree engine: a name is not evidence."""
    src = """
    function h2(c) { a.innerHTML = c; }
    h2("<b>static</b>");
    """
    assert _flows(src) == []


def test_a_sink_with_no_caller_is_not_a_flow():
    src = """
    function unused(c) { a.innerHTML = c; }
    """
    assert _flows(src) == []


def test_each_parameter_is_matched_by_position():
    src = """
    function render(title, body) { a.innerHTML = body; }
    render("hello", location.hash);
    """
    assert ("innerHTML", "location.hash") in _flows(src)


def test_a_positional_match_does_not_leak_into_the_wrong_parameter():
    src = """
    function render(title, body) { a.innerHTML = body; }
    render(location.hash, "constant");
    """
    assert _flows(src) == []


def test_an_omitted_argument_does_not_taint_the_parameter_it_would_have_filled():
    src = """
    function render(title, body) { a.innerHTML = body; }
    render(location.hash);
    """
    assert _flows(src) == []


def test_a_parameter_keeps_caller_taint_when_it_has_a_default():
    src = """
    function show(v = "") { a.innerHTML = v; }
    show(location.search);
    """
    assert ("innerHTML", "location.search") in _flows(src)


def test_a_parameter_takes_its_default_when_no_argument_is_passed():
    src = """
    function show(v = location.hash) { a.innerHTML = v; }
    show();
    """
    assert ("innerHTML", "location.hash") in _flows(src)


def test_a_function_expression_assigned_to_a_name_propagates_too():
    src = """
    var paint = function (v) { a.innerHTML = v; };
    paint(document.URL);
    """
    assert ("innerHTML", "document.URL") in _flows(src)


def test_an_arrow_function_propagates_too():
    src = """
    const paint = (v) => { a.innerHTML = v; };
    paint(window.name);
    """
    assert ("innerHTML", "window.name") in _flows(src)


def test_two_call_sites_one_of_them_tainted_is_enough():
    src = """
    function h2(c) { a.innerHTML = c; }
    h2("static");
    h2(location.search);
    """
    assert ("innerHTML", "location.search") in _flows(src)


def test_a_parameter_written_to_a_method_sink_propagates():
    src = """
    function add(html) { el.insertAdjacentHTML("beforeend", html); }
    add(location.hash);
    """
    assert ("insertAdjacentHTML", "location.hash") in _flows(src)


def test_a_recursive_helper_that_taints_itself_is_not_a_flow():
    """A function calling itself with its own parameter proves nothing."""
    src = """
    function h2(c) { if (c) { h2(c); } a.innerHTML = c; }
    """
    assert _flows(src) == []


def test_a_caller_after_the_callee_still_propagates():
    """Hoisting is real: a call before the declaration reaches the same symbol."""
    src = """
    h2(location.search);
    function h2(c) { a.innerHTML = c; }
    """
    assert ("innerHTML", "location.search") in _flows(src)


def test_a_function_whose_sink_ignores_its_parameter_is_not_joined_by_name():
    """A minified bundle's one-letter helpers collide with later parameters.

    ``hash`` is a parameter somewhere far below, and thousands of calls pass a
    value that happens to be a source. Joining on the name alone would taint
    every one of them; the body has to prove a parameter reaches a sink.
    """
    src = """
    function D2() { this.size = 0; this.__data__ = { hash: new Uc }; }
    function O2(e) { return typeof e; }
    D2(location.hash);
    O2(location.search);
    """
    assert _flows(src) == []


def test_a_jquery_helper_that_writes_its_parameter_is_joined():
    """The shape a bundle uses for jQuery: ``$(sel).html(value)``."""
    src = """
    function renderInto(sel, value) { $(sel).html(value); }
    renderInto("#out", location.hash);
    """
    assert ("jquery.html", "location.hash") in _flows(src)
