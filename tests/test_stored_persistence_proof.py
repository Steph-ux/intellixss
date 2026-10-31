"""A stored sink is credited to the endpoint that keeps the record.

Two shapes of "answered but did not store" were both counted as stored XSS on
Juice Shop:

- a handler that answers ``status: success`` for a field it ignores, so the
  value was never read back yet the lead survived because the *response* looked
  like a write;
- a value that was read back, but only because the read repeated the query the
  write was sent with. The listing echoed what it was asked, not a record.

Both are settled by reading the value back with no payload in the request. A
page that answers the clean URL and still carries the value is showing its
record; a page that answers without it was only echoing. The reads happen once
per endpoint and field, before the payloads, so the check cannot overwrite the
record it is checking.
"""

import asyncio

import pytest

from intellixss.plugins import stored_xss as S

URL = "http://127.0.0.1:3000/rest/products/1/reviews"
PAGE = "http://127.0.0.1:3000/post?postId=1"


class _Handler:
    """A handler that answers a write, and a reader that renders a page."""

    def __init__(self, *, keeps: bool, clean_page: str = "record", checks_url: bool = False):
        """
        *clean_page* is what the page without any query shows:
        ``record`` reads the stored value, ``echo`` shows the query it was
        given, ``empty`` shows a page with nothing on it.

        *checks_url* makes the handler validate the field as a URL and refuse a
        value that carries no scheme, which is what a ``website`` field does.
        """
        self.keeps = keeps
        self.clean_page = clean_page
        self.checks_url = checks_url
        self.stored = ""
        self.reads = []
        self.writes = []

    def _write(self, url, field, value, method, base):
        body = dict(base or {})
        body[field] = value
        self.writes.append((method, url, body))
        if self.checks_url and not value.startswith(("http://", "https://", "//")):
            return 400, '{"error":"not a url"}', {}, url
        # Only the field the handler reads is kept, exactly as the review
        # endpoint stores ``message`` and ignores ``review``.
        if self.keeps and field == "message":
            self.stored = value
        return 201, '{"status":"success"}', {}, url

    async def inject(self, url, field, value, method="GET", base_data=None):
        return self._write(url, field, value, method, base_data)

    async def inject_json(self, url, field, value, base=None, method="POST"):
        return self._write(url, field, value, method, base)

    async def request(self, method, url, **kwargs):
        self.reads.append(url)
        if "?" in url:
            if self.keeps:
                return 200, f"<html><body><li>{self.stored}</li></body></html>", {}, url
            return 200, "<html><body>nothing here</body></html>", {}, url
        if self.clean_page == "record" and self.stored:
            return 200, f"<html><body><li>{self.stored}</li></body></html>", {}, url
        if self.clean_page == "echo":
            return 200, "<html><body>no results</body></html>", {}, url
        return 200, "<html><body>nothing here</body></html>", {}, url


def prove(client, field="message", handler=URL, page=PAGE, data=None):
    return asyncio.run(
        S._prove_persistence(client, handler, page, field, "PUT", dict(data or {}))
    )


def test_a_record_that_is_kept_is_proven():
    client = _Handler(keeps=True)
    assert prove(client) is not None
    # Written once, read back twice on the page asked for, then once on the
    # page without the query, which is where an echo would come from.
    assert len(client.writes) == 1
    assert client.writes[0][1] == URL, "the proof writes to the handler, not the page"
    assert client.reads == [PAGE, PAGE, "http://127.0.0.1:3000/post"]


def test_the_proof_reads_the_page_and_writes_the_handler():
    """A form handler answers ``405`` to a write sent to the page it renders.

    The endpoint that keeps the record and the document that shows it are two
    different URLs. Sending the proof to the page asks a static document to
    store something, and refusing it there discards a record the handler kept.
    """
    client = _Handler(keeps=True)
    assert prove(client) is not None
    assert client.writes[0][1] == URL
    assert all(URL not in r for r in client.reads)


def test_a_handler_that_answers_but_ignores_the_field_is_refuted():
    client = _Handler(keeps=True)
    assert prove(client, field="review") is None


def test_a_handler_that_keeps_nothing_is_refuted():
    client = _Handler(keeps=False)
    assert prove(client) is None
    assert client.writes


def test_a_listing_that_only_echoes_the_query_is_refuted():
    client = _Handler(keeps=False, clean_page="echo")
    assert prove(client) is None


@pytest.mark.parametrize("data", [{"message": "test"}, {}])
def test_the_probe_restores_the_callers_fields(data):
    original = dict(data)
    assert prove(_Handler(keeps=True), data=data) is not None
    assert data == original


def test_a_url_field_is_proved_with_a_value_that_is_a_url():
    """A ``website`` field refuses a value with no scheme, payloads included.

    The payloads the caller writes carry their own origin; a bare canary would
    be refused as a URL where every payload was accepted, and the field would be
    dropped with a proof that asked a different question than the payloads.
    """
    client = _Handler(keeps=True, checks_url=True)
    assert prove(client) is not None
    written = client.writes[0][2]["message"]
    assert written.startswith("http://"), written


def test_a_url_field_that_stores_nothing_is_still_refuted():
    client = _Handler(keeps=False, checks_url=True, clean_page="empty")
    assert prove(client) is None


def test_the_query_a_page_echoes_is_stripped():
    assert S._strip_query(PAGE) == "http://127.0.0.1:3000/post"


def test_the_record_parameter_is_the_one_removed():
    assert S._without_the_record_parameter(PAGE) == "http://127.0.0.1:3000/post"


def test_the_rest_of_the_query_stays_with_the_page():
    """``/post`` alone is a different resource and may answer ``400``.

    Dropping the whole query asks the site for a document it does not serve,
    and a page that cannot answer is not evidence that it echoed.
    """
    assert (
        S._without_the_record_parameter("http://lab.test/post?postId=9&lang=fr")
        == "http://lab.test/post?lang=fr"
    )


def test_a_page_without_a_record_parameter_keeps_its_query():
    page = "http://lab.test/search?q=app"
    assert S._without_the_record_parameter(page) == page


def test_a_refused_clean_read_keeps_a_clinched_record():
    """The readable page carried the value twice; the clean read is not decisive.

    An article site answers ``/post`` with ``400``. Reading that is neither a
    record nor an echo, so it cannot refute a value that was already read back
    from the page the record belongs to.
    """
    client = _Handler(keeps=True)
    assert prove(client) is not None


class _Encoding:
    """Records which encoding each write arrived in."""

    def __init__(self) -> None:
        self.forms = 0
        self.json = 0

    async def inject(self, url, field, value, method="GET", base_data=None):
        self.forms += 1
        return 201, "{}", {}, url

    async def inject_json(self, url, field, value, base=None, method="POST"):
        self.json += 1
        return 201, "{}", {}, url

    async def request(self, method, url, **kwargs):
        return 200, "<html><body>nothing</body></html>", {}, url


def test_a_form_handler_is_written_with_form_fields():
    """A form endpoint answers ``405`` to a JSON body it never reads."""
    client = _Encoding()
    asyncio.run(S._prove_persistence(client, URL, PAGE, "message", "POST", {}))
    assert (client.forms, client.json) == (1, 0)


def test_an_api_target_is_written_with_json():
    """A JSON endpoint rejects form fields, and drops the proof with them."""
    client = _Encoding()
    asyncio.run(
        S._prove_persistence(client, URL, PAGE, "message", "POST", {}, json_body=True)
    )
    assert (client.forms, client.json) == (0, 1)
