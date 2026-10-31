"""A writing scan removes what it created, and only what it can prove it created.

The scanner posts comments, reviews and messages to prove a stored sink. Those
writes stay on the target until someone deletes them by hand, which is the one
lasting side effect of a scan. These tests pin the cleanup rules:

* only a URL the plugin resolved from an identifier the target returned is
  deleted; a pattern-derived guess is never used, because it would remove
  records belonging to real users;
* a read-only scan sends no DELETE, even if a leftover registration exists;
* removal happens in reverse creation order, so a child is gone before its
  parent;
* what cannot be removed is reported with its surface, not silently dropped.
"""

import asyncio

import pytest

from intellixss.config import Config
from intellixss.http.client import HttpClient
from intellixss.scanner.cleanup import clean_written, cleanup_summary


class _FakeClient:
    """An HttpClient stand-in that records requests instead of sending them."""

    def __init__(self, status: int = 204):
        self.config = Config(writes=True)
        self.written = []
        self.sent = []
        self.status = status

    def note_write(self, *a, **kw):
        return HttpClient.note_write(self, *a, **kw)

    async def request(self, method, url, **kw):
        self.sent.append((method, url))
        return self.status, "", {}, url


def _client(status: int = 204, writes: bool = True) -> _FakeClient:
    c = _FakeClient(status)
    c.config = Config(writes=writes)
    return c


def test_a_registered_delete_is_sent_and_counted_as_removed():
    c = _client()
    c.note_write("reviews", "https://t/rest/products/1/reviews", "PUT",
                 delete_url="https://t/rest/products/1/reviews/42")
    rows = asyncio.run(clean_written(c))
    assert c.sent == [("DELETE", "https://t/rest/products/1/reviews/42")]
    assert rows[0]["removed"] == 1
    assert cleanup_summary(rows)["removed"] == 1


def test_a_read_only_scan_sends_no_delete_at_all():
    c = _client(writes=False)
    c.note_write("reviews", "https://t/r", "POST", delete_url="https://t/r/1")
    rows = asyncio.run(clean_written(c))
    assert c.sent == []
    assert rows[0]["removed"] == 0
    # The URL is still known, so this is a refusal rather than an impossibility.
    assert rows[0]["cleanable"] is True
    assert cleanup_summary(rows)["removed"] == 0


def test_a_record_without_an_identifier_is_reported_not_deleted():
    c = _client()
    c.note_write("feedback", "https://t/api/Feedbacks", "POST")
    rows = asyncio.run(clean_written(c))
    assert c.sent == []
    summary = cleanup_summary(rows)
    assert summary["cleanable"] == 0
    assert summary["uncleanable"] == 1
    assert summary["surfaces"] == ["feedback"]


def test_records_are_removed_in_reverse_creation_order():
    c = _client()
    c.note_write("a", "https://t/a", "POST", delete_url="https://t/a/1")
    c.note_write("b", "https://t/b", "POST", delete_url="https://t/b/2")
    asyncio.run(clean_written(c))
    assert [u for _m, u in c.sent] == ["https://t/b/2", "https://t/a/1"]


def test_a_refused_delete_is_recorded_as_not_removed():
    c = _client(status=403)
    c.note_write("reviews", "https://t/r", "POST", delete_url="https://t/r/9")
    rows = asyncio.run(clean_written(c))
    assert rows[0]["removed"] == 0
    assert "403" in str(rows[0]["reason"])


def test_a_record_the_target_already_lost_counts_as_clean():
    """404 means gone: the target is clean, and saying otherwise misleads."""
    c = _client(status=404)
    c.note_write("reviews", "https://t/r", "POST", delete_url="https://t/r/9")
    rows = asyncio.run(clean_written(c))
    assert rows[0]["removed"] == 1


def test_the_summary_counts_both_kinds_together():
    c = _client()
    c.note_write("reviews", "https://t/r", "POST", delete_url="https://t/r/1")
    c.note_write("feedback", "https://t/f", "POST")
    summary = cleanup_summary(asyncio.run(clean_written(c)))
    assert summary == {
        "records": 2,
        "cleanable": 1,
        "removed": 1,
        "uncleanable": 1,
        "surfaces": ["feedback", "reviews"],
    }


def test_nothing_registered_means_nothing_sent():
    c = _client()
    assert asyncio.run(clean_written(c)) == []
    assert c.sent == []
