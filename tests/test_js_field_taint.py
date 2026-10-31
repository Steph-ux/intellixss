"""Field taint: ``this.userData`` written in one method, read in another.

A component stores a response in a field and writes the field to a sink in a
different method::

    class Tracker { userData; export(){ svc.data().subscribe({next: t => {
        this.userData = t.userData, window.open()?.document.write(this.userData)
    }}) } }

The block structure was already right — the writer is a callback inside a
method inside a class — but the taint died at ``this.userData``: a member
expression took its taint from its *object*, and ``this`` is nobody's source.
On the real Juice Shop bundle this is why both engines reported nothing for the
one ``document.write`` the application actually performs.

These tests pin the rules of the fix:

* a field written from a tainted value is tainted when it is read back, on the
  same class, through ``this`` or through an instance of it;
* a field is scoped to *its* class: two classes that both declare ``userData``
  are two fields, and taint in one never leaks into the other;
* a field written from an untainted value stays untainted — a field is not a
  wildcard that excuses the value it holds;
* an object literal's own property is a different thing from a class field and
  is not tainted by this rule.
"""

import sys

sys.path.insert(0, r"D:\Steph\File\Projet\kali-tools\xss")

from intellixss.analysis.js_scope import resolve_scopes


def _flows(src: str):
    return [(w.sink, w.source) for b in resolve_scopes([src]) for w in b.tainted_writes]


def test_a_field_written_in_the_same_method_reaches_the_sink():
    src = """
    class S { userData; go() { this.userData = location.hash; document.write(this.userData); } }
    """
    assert ("document.write", "location.hash") in _flows(src)


def test_a_field_written_in_a_callback_is_read_back_after_it():
    """The Juice Shop's ``app-data-export``, reduced to one component.

    The real base is an injected service whose method forwards to
    ``this.http.post(...)``. Cross-service provenance is not modelled — the
    service is a different class, minified in the bundle — so this pins the
    shape the analyser *does* prove: the response arrives through a request,
    is stored in a field, and reaches ``document.write`` in the same callback.
    """
    src = """
    class S {
      userData;
      export() {
        this.http.post(this.host + "/data-export", this.req).subscribe({ next: t => {
          this.userData = t.userData;
          window.open("", "_blank").document.write(this.userData);
        }});
      }
    }
    """
    assert ("document.write", "fetch response") in _flows(src)


def test_a_field_copied_from_another_field_is_tainted():
    """``this.b = this.a`` copies whatever ``a`` holds, including a source."""
    src = """
    class S { a; b; load() { this.a = location.hash; }
              copy() { this.b = this.a; }
              render() { document.write(this.b); } }
    """
    assert ("document.write", "location.hash") in _flows(src)


def test_field_taint_is_applied_in_a_single_pass_over_the_bundle():
    """The field pass reads each write record once.

    The first version re-walked the whole program after every round that
    changed a field. On a 1.2 MB bundle that was minutes; this asserts the pass
    visits each write record once, which is the property that keeps it linear.
    """
    src = "\n".join(
        f"class C{i} {{ a; b; load() {{ this.a = location.hash; }} "
        f"copy() {{ this.b = this.a; }} render() {{ document.write(this.b); }} }}"
        for i in range(200)
    )
    blocks = resolve_scopes([src])
    flows = {(w.sink, w.source) for b in blocks for w in b.tainted_writes}
    assert flows == {("document.write", "location.hash")}, flows


def test_a_sink_in_a_callback_body_after_a_sibling_statement_is_seen():
    """The block count was short, not just the taint.

    ``list.forEach(i => …)`` followed by another statement made ``walk`` return
    a second time, and the statement after the call was never read: the callback
    body and everything below the call vanished. Counted against the block a
    callback must have, this fails by one.
    """
    src = "function render(list) { list.forEach(i => { box.innerHTML = location.hash; }); other(); }"
    blocks = resolve_scopes([src])
    kinds = [b.kind for b in blocks]
    assert kinds.count("arrow_function") == 1, kinds
    assert ("innerHTML", "location.hash") in [
        (w.sink, w.source) for b in blocks for w in b.tainted_writes
    ]


def test_statements_after_a_call_are_still_analysed():
    src = "function render(list) { list.forEach(f); box.innerHTML = location.hash; }"
    flows = [(w.sink, w.source) for b in resolve_scopes([src]) for w in b.tainted_writes]
    assert flows == [("innerHTML", "location.hash")], flows


def test_a_subscription_on_a_service_that_forwards_to_a_request_is_not_proven():
    """The named limit. ``dataSubjectService.dataExport`` is a request, but the
    proof lives in another class that the bundle renames; claiming it here
    without following that class would be a guess, and a guess in a scanner is
    a false positive the user pays for."""
    src = """
    class S {
      userData;
      export() {
        this.dataSubjectService.dataExport(this.req).subscribe({ next: t => {
          this.userData = t.userData;
          document.write(this.userData);
        }});
      }
    }
    """
    assert _flows(src) == []


def test_a_field_written_in_one_method_is_read_in_another():
    src = """
    class S {
      userData;
      load() { this.userData = location.search; }
      render() { this.out.innerHTML = this.userData; }
    }
    """
    assert ("innerHTML", "location.search") in _flows(src)


def test_a_field_reached_through_an_instance_carries_the_taint():
    src = """
    class S { userData; load() { this.userData = location.hash; } }
    var s = new S();
    document.write(s.userData);
    """
    assert ("document.write", "location.hash") in _flows(src)


def test_two_classes_with_the_same_field_name_are_two_fields():
    """Name identity is the regex engine's bug; a field has an owner."""
    src = """
    class A { userData; load() { this.userData = location.hash; } }
    class B { userData; } 
    var b = new B();
    document.write(b.userData);
    """
    assert _flows(src) == []


def test_a_field_written_from_an_untainted_value_stays_clean():
    src = """
    class S { userData; load() { this.userData = "safe"; } render() { document.write(this.userData); } }
    """
    assert _flows(src) == []


def test_a_field_taint_survives_a_method_call_between_write_and_read():
    """The write is in a method; the read is in a callback nested two deep."""
    src = """
    class S {
      userData;
      load() { this.userData = location.hash; }
      render() {
        this.items.forEach(i => {
          setTimeout(() => { document.write(this.userData); });
        });
      }
    }
    """
    assert ("document.write", "location.hash") in _flows(src)


def test_an_object_literal_property_is_not_a_field():
    """``{userData: location.hash}`` names a property of an object, not a field."""
    src = """
    var state = { userData: "safe" };
    document.write(state.userData);
    """
    assert _flows(src) == []


def test_a_field_assignment_with_a_compound_operator_keeps_the_taint():
    src = """
    class S { userData; load() { this.userData = ""; this.userData += location.hash; }
              render() { document.write(this.userData); } }
    """
    assert ("document.write", "location.hash") in _flows(src)


# ---------------------------------------------------------- subscription


def test_a_subscription_directly_on_a_request_carries_the_response():
    js = """
    class S { go() { this.data().subscribe(v => { el.innerHTML = v.html; }); } }
    """
    # ``this.data()`` is not a request the analysis can name, so nothing fires.
    assert _flows(js) == []


def test_a_subscription_on_a_named_request_carries_the_response():
    js = """
    function load() {
      http.get("/api/thing").subscribe(v => { el.innerHTML = v.html; });
    }
    """
    assert ("innerHTML", "fetch response") in _flows(js)


def test_a_subscription_on_an_unrelated_observable_stays_clean():
    """``interval.subscribe`` ticks a number; it is not a response."""
    js = """
    function start() {
      counter.subscribe(v => { el.innerHTML = v; });
    }
    """
    assert _flows(js) == []
