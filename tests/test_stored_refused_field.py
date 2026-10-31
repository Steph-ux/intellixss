"""A write that cannot become a record is settled once, not once per payload.

A stored pass writes a canary, reads the page, then writes each payload in turn
and looks for it. When the handler answered the canary with a refusal, every
payload is refused for the same reason the canary was, and none of them is
measured against anything. When the handler accepts it, shows it, and the next
read has forgotten it, the field owns no record either. Both are settled by the
canary; sending six payloads to discover it costs twelve requests and says
nothing new.

The case that must *not* be settled early is the opposite one: the record really
is kept, so every payload has to be measured against the page that renders it.
"""

from __future__ import annotations

import asyncio

from intellixss.plugins.stored_xss import scan_server_stored

PAGE = "http://lab.test/post?postId=9"
HANDLER = "http://lab.test/post/comment"


class _Site:
    """A form page and the handler it posts to.

    *keeps* is what the handler does with an accepted value:

    - ``"kept"``: the record is stored and rendered on the page.
    - ``"dropped"``: the handler answers ``200`` and the page shows nothing —
      the endpoint accepted a body it never stored.
    - ``"refused"``: the handler rejects the field outright, with ``400``.
    """

    def __init__(self, *, keeps="kept", accepts=("comment", "name"), posted_in_place=False):
        self.keeps = keeps
        self.accepts = set(accepts)
        self.record = ""
        self.writes = 0
        # A handler that answers a status instead of a document.
        self.answers_with_no_content = False
        # What the page shows for a write that was answered but not kept.
        self.echoed = ""
        # A form whose ``action`` is the page that renders it posts in place, so
        # a successful write is readable straight from the handler's response.
        self.posted_in_place = posted_in_place

    def _document(self, records: str) -> str:
        return (
            "<!doctype html><html><body>"
            f"<article>{records}</article>"
            f'<form method="post" action="{HANDLER}">'
            '<input type="hidden" name="csrf" value="tok">'
            '<input type="hidden" name="postId" value="9">'
            '<textarea name="comment"></textarea>'
            '<input type="text" name="name">'
            '<input type="email" name="email">'
            '<input type="text" name="website">'
            "</form></body></html>"
        )

    async def request(self, method, url, **kw):
        if method.upper() == "GET":
            shown = self.echoed or self.record
            # The echoed value is shown once: a listing that renders the
            # submitted value has forgotten it by the next read.
            self.echoed = ""
            records = f'<div class="record">{shown}</div>' if shown else ""
            return 200, self._document(records), {}, url
        # ``_submit`` reaches the handler through this door for a form write:
        # the field being written is the one the pass put its value into.
        body = dict(kw.get("data") or kw.get("json_body") or {})
        field = kw.get("field") or ("comment" if "comment" in body else "name")
        return await self._write(field, body)

    async def _write(self, field, base):
        self.writes += 1
        value = (base or {}).get(field, "")
        if self.keeps == "refused" or field not in self.accepts:
            return 400, "refused", {}, HANDLER
        if self.keeps == "echoes_its_write":
            # The page shows what was just written, and shows nothing once that
            # write has been read: the handler answered and kept no record.
            self.echoed = value
            return 200, "posted", {}, HANDLER + "/confirmation"
        self.record = value
        if self.answers_with_no_content:
            return 204, "", {}, HANDLER
        return 200, "posted", {}, HANDLER + "/confirmation"

    async def inject(self, url, field, value, method="GET", base_data=None):
        return await self._write(field, base_data)

    async def inject_json(self, url, field, value, base=None, method="POST"):
        return await self._write(field, base)


def stored(site: _Site, field: str = "comment"):
    return asyncio.run(
        scan_server_stored(
            site,
            HANDLER,
            field=field,
            base_data={},
            render_urls=[PAGE],
            browser=None,
        )
    )


async def _writes_for(site: _Site, field: str = "comment", page: str = PAGE):
    """Run a stored pass and report how many writes it made.

    The number of writes is the whole question: a payload written to a field
    whose canary is not rendered is then read back from a page that cannot show
    it, and the answer was already settled by the canary.
    """
    await scan_server_stored(
        site,
        page,
        field=field,
        base_data={},
        render_urls=[page],
        browser=None,
    )
    return site.writes


def test_a_refused_write_is_answered_by_its_canary_alone():
    """The handler said no to the canary; it says no to every payload too."""
    site = _Site(keeps="refused")
    findings = stored(site)
    assert site.writes == 1, site.writes
    assert not findings


def test_a_write_that_keeps_nothing_is_answered_by_its_canary_alone():
    """A page that shows the canary once and then drops it is not a record.

    The form posts to the page that renders it, so the write is read straight
    from the handler's response — and a listing that renders the submitted
    value looks exactly like a stored record until it is read again. Reading it
    again with nothing written in between is the only thing that separates the
    two, and it is the difference between measuring six payloads against a real
    record and measuring them against a page that has already forgotten them.
    """
    site = _Site(keeps="echoes_its_write", posted_in_place=True)
    assert asyncio.run(_writes_for(site, page=PAGE)) == 1


def test_a_read_that_returned_no_document_does_not_settle_the_field():
    """``204`` is not "not kept": the record was never looked at.

    A handler that answers a status has not said what the page renders. Ending
    the field there would drop a real sink behind a handler that answers ``204``
    and whose page is fetched separately.
    """
    site = _Site(keeps="kept")
    site.answers_with_no_content = True
    findings = stored(site)
    assert site.writes > 1, site.writes
    assert findings, "the page renders the record, whatever the handler answered"


def test_a_kept_record_is_measured_with_every_payload():
    site = _Site(keeps="kept")
    findings = stored(site)
    assert site.writes > 1
    assert findings, "a page that renders the record is a sink"
