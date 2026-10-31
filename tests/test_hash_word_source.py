"""A member named ``hash`` is not the URL fragment.

``(r"\\bhash\\b(?!\\s*=)", "location.hash")`` accepted the *word* ``hash``
anywhere: an object key (``{hash: new Uc}``), a string literal
(``t[`hash`]``), a method name. On a minified bundle that is enough to bind a
one-letter variable to ``location.hash`` — ``a=…?`string`:`hash`]:t.map`` —
and the name then reaches every sink its window over the file.
"""

from intellixss.analysis.static_dom import _tainted_vars, analyze_dom_flows

LODASH_JS = (
    "function D2(){this.size=0,this.__data__={hash:new Uc,map:new(ea||ta),string:new Uc}}"
    "function R2(e){var a=e.__data__;return wf(a)?t[typeof a==`string`?`string`:`hash`]:t.map}"
)


def test_an_object_key_named_hash_is_not_the_location_hash():
    taint = _tainted_vars(LODASH_JS)
    assert "a" not in taint
    assert "__data__" not in taint


def test_a_string_literal_named_hash_is_not_the_location_hash():
    taint = _tainted_vars('var k = t["hash"]; var out = document.getElementById("o");')
    assert "k" not in taint


def test_the_former_broken_bundle_reports_no_flow():
    js = (
        LODASH_JS
        + "function L2(e){var a=e.__data__;"
        "$('#x').html(a);}"
    )
    assert analyze_dom_flows("", [js]) == []


def test_the_shorthand_of_a_url_fragment_still_counts():
    """``hash`` as a *variable* is still the fragment the page read."""
    js = (
        "var hash = location.hash.substring(1);"
        "document.getElementById('o').innerHTML = hash;"
    )
    assert ("location.hash", "innerHTML", "html") in analyze_dom_flows("", [js])
