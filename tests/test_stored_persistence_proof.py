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

    def __init__(self, *, keeps: bool, clean_page: str = "record"):
        """
        *clean_page* is what the page without any query shows:
        ``record`` reads the stored value, ``echo`` shows the query it was
        given, ``empty`` shows a page with nothing on it.
        """
        self.keeps = keeps
        self.clean_page = clean_page
        self.stored = ""
        self.reads = []
        self.writes = []

    def _write(self, url, field, value, method, base):
        body = dict(base or {})
        body[field] = value
        self.writes.append((method, url, body))
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


def prove(client, field="message", url=URL, data=None):
    return asyncio.run(
        S._prove_persistence(client, url, field, "PUT", dict(data or {}))
    )


def test_a_record_that_is_kept_is_proven():
    client = _Handler(keeps=True)
    assert prove(client, url=PAGE) is not None
    # Written once, read back twice on the page asked for, then once on the
    # page without the query, which is where an echo would come from.
    assert len(client.writes) == 1
    assert client.reads == [PAGE, PAGE, "http://127.0.0.1:3000/post"]


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


def test_the_query_a_page_echoes_is_stripped():
    assert S._strip_query(PAGE) == "http://127.0.0.1:3000/post"
