"""A ``src`` is a URL or a document depending on the element that receives it.

The regex engine labels every ``.src = fragment`` as ``script_or_img_src``, which
is right for a created ``<script>`` and right for an ``<img>`` the browser
fetches, but the four URL-sink fixtures ask for a different shape each: an
``<iframe>`` loads a document, an ``<a>.href``/``location`` navigates, and an
``f.action`` submits. The tree engine saw none of them, so every one of those
cases was served by the regex engine alone.

The distinction is made from the element the variable was created as, never from
the variable's name: ``var s`` says nothing, and a scanner that guesses from a
name is guessing.
"""

import sys

sys.path.insert(0, r"D:\Steph\File\Projet\kali-tools\xss")

from intellixss.analysis.js_scope import resolve_scopes


def _flows(src: str):
    blocks = resolve_scopes([src])
    return {(w.source, w.sink) for b in blocks for w in b.tainted_writes}


def test_a_created_iframe_is_a_document_sink_not_a_script_on_a_guess():
    src = """
    var payload = document.location.hash.substr(1);
    var iframe = document.createElement("iframe");
    iframe.src = payload;
    document.body.appendChild(iframe);
    """
    flows = _flows(src)
    assert ("location.hash", "frame_src") in flows, flows


def test_a_created_script_is_a_script_sink():
    src = """
    var payload = document.location.hash.substr(1);
    var s = document.createElement("script");
    s.src = "/static/" + payload;
    document.body.appendChild(s);
    """
    flows = _flows(src)
    assert ("location.hash", "script_or_img_src") in flows, flows


def test_a_document_location_source_is_a_location_hash_source():
    """``document.location.hash`` is ``location.hash`` and is labelled as such.

    The regex engine reports the short spelling, and a page written the long
    way was served by that engine alone. Matching the tree must not rename one
    flow into two: the qualified member is followed to the source it names.
    """
    src = """
    var payload = document.location.hash.substr(1);
    el.innerHTML = payload;
    """
    assert ("location.hash", "innerHTML") in _flows(src)


def test_an_unidentified_receiver_is_still_reported():
    """``other.src`` may be anything: report the flow, do not drop it.

    The receiver rule only chooses a payload family for a *proven* element. An
    unproven one keeps the generic ``src`` reading, because reporting nothing
    would be the false negative this engine exists to remove.
    """
    src = """
    function go(other) {
      var v = location.search;
      other.src = v;
    }
    """
    assert ("location.search", "script_or_img_src") in _flows(src)


def test_assignment_to_location_is_a_navigation_sink():
    src = """
    var payload = document.location.hash.substr(1);
    document.location.href = payload;
    """
    flows = _flows(src)
    assert ("location.hash", "location_assign") in flows, flows


def test_assigning_the_location_object_itself_is_a_navigation():
    """``location = url`` navigates, and so does ``document.location = url``.

    An assignment to an identifier is read as a variable write, so the
    navigation never reached the ``href`` sink. The receiver is the global
    ``location``, which ``document.``/``window.`` merely names.
    """
    for lhs in ("location", "document.location", "window.location"):
        src = f"function go() {{ {lhs} = location.search; }}"
        assert ("location.search", "location_assign") in _flows(src), lhs


def test_assigning_location_to_a_local_is_not_a_sink():
    """``var here = location`` reads the object; it navigates nowhere."""
    src = """
    function go() {
      var here = location;
      return here;
    }
    """
    assert _flows(src) == set()


def test_a_sink_whose_receiver_never_mentions_the_source_is_a_flow():
    """``other.src = v``: the receiver is an identifier, the *value* is tainted.

    Reading the sink's receiver as its data is the mistake the regex window
    makes on a bundle: ``evaluate(payload)`` was reported as ``eval``. A sink is
    a sink because of its argument, whatever the receiver is called.
    """
    src = """
    function attach(el) {
      var v = location.search;
      el.src = v;
    }
    """
    assert ("location.search", "script_or_img_src") in _flows(src)


def test_eval_runs_the_string_a_source_reaches():
    src = """
    var payload = window.name;
    eval(payload);
    """
    assert ("window.name", "eval") in _flows(src)


def test_a_code_argument_is_a_code_sink_whatever_is_handed_to_the_timer():
    """``setTimeout(payload, 10)`` parses a string.

    The analysis cannot type a variable, and the regex engine reads this shape
    as ``eval``; withholding it would be the false negative the tree engine
    exists to remove. Reported under ``eval``, and pinned as such rather than
    left to whichever engine happens to answer.
    """
    src = """
    var payload = window.name;
    setTimeout(payload, 10);
    """
    assert ("window.name", "eval") in _flows(src)


def test_a_form_action_is_a_form_sink():
    src = """
    var payload = document.location.hash.substr(1);
    var f = document.createElement("form");
    f.action = payload;
    document.body.appendChild(f);
    """
    flows = _flows(src)
    assert ("location.hash", "form_action") in flows, flows
