"""A handler verdict is not a render page, and a fragment is not every parameter.

Two confusion bugs hid a real sink each:

* The stored pass re-read a handler that answered with a one-line sentence (a
  guard, a validation error) and then called the record "not persisted". Even
  when it correctly found nothing, the caller treated that as "this field is
  answered" and skipped the reflected pass on the *page that renders it*.
* ``#fragment`` is the name invented for the URL hash. An owned sink whose page
  also reads script sources has no fragment, so delivering it as
  ``#fragment=<payload>`` drops the parameter the page needs to render at all.
"""

from intellixss.plugins.stored_xss import _renders_records
from intellixss.scanner.orchestrator import _is_fragment_name


def test_a_document_is_a_render_page():
    assert _renders_records(200, "<html><body><p>comment</p></body></html>")


def test_a_one_line_verdict_is_not_a_render_page():
    assert not _renders_records(200, '"Invalid CSRF token"')
    assert not _renders_records(200, "Thanks for your comment")
    assert not _renders_records(200, "")


def test_a_failed_fetch_is_not_a_render_page():
    assert not _renders_records(0, "")


def test_a_fragment_pseudo_parameter_is_recognised():
    for name in ("#fragment", "fragment", "#"):
        assert _is_fragment_name(name), name


def test_a_real_parameter_is_never_delivered_as_a_fragment():
    for name in ("email", "search", "q", "content"):
        assert not _is_fragment_name(name), name
