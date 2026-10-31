"""A field is credited only when the page keeps markup, and the measurement is real.

A server that strips tags with its own regular expression leaves the canary in
place and destroys every element, so the field is reported as a live sink on the
strength of a probe that carries nothing executable. The check is a second
write: a value whose only distinguishing feature is a tag, read back once. A
page that returns the text and drops the tag has answered the question; a page
that keeps it is a sink the payloads are built for.

The check may only ever remove a claim, and a check that could not be made — no
page to read, a handler that refused the probe — leaves the finding as it was.
"""

import asyncio

from intellixss.plugins.stored_xss import scan_server_stored


class _Handler:
    """One stored record; the page renders its value inside a form field."""

    PAGE = """<!doctype html><html><body>
    <article><form method="post" action="/note">
      <input type="text" name="comment" value="{value}">
    </form></article></body></html>"""

    # The same handler whose list renders the record as markup. Nothing is
    # stripped here either; the difference is where the page puts the value.
    PAGE_LIVE = """<!doctype html><html><body>
    <article><ul><li class="note">{value}</li></ul>
    <form method="post" action="/note">
      <input type="text" name="comment">
    </form></article></body></html>"""

    def __init__(self, sanitise: bool, live_markup: bool = False) -> None:
        self.sanitise = sanitise
        self.live_markup = live_markup
        self.value = ""
        self.writes: list[tuple[str, str]] = []
        self.reads = 0

    async def inject(self, url, field, value, method="POST", base_data=None):
        self.writes.append((field, value))
        self.value = _strip_tags(value) if self.sanitise else value
        return 302, "", {}, url

    async def inject_json(self, url, field, value, base=None, method="POST"):
        # Every write goes through the same handler, whichever encoding the
        # endpoint takes.
        return await self.inject(url, field, value, method=method, base_data=base)

    async def request(self, method, url, **kw):
        self.reads += 1
        page = self.PAGE_LIVE if self.live_markup else self.PAGE
        return 200, page.format(value=self.value), {}, url


def _strip_tags(value: str) -> str:
    out, depth = [], 0
    for ch in value:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif not depth:
            out.append(ch)
    return "".join(out)


def _scan(handler: _Handler):
    return asyncio.run(
        scan_server_stored(
            handler,
            "http://x.test/note",
            field="comment",
            base_data={},
            render_urls=["http://x.test/note"],
            browser=None,
        )
    )


def test_a_field_that_drops_markup_is_credited_as_a_reflection():
    kinds = {f.vulnerability_type for f in _scan(_Handler(sanitise=True))}
    assert kinds and kinds == {"reflection"}, kinds


def test_a_field_that_keeps_markup_stays_a_stored_sink():
    kinds = {f.vulnerability_type for f in _scan(_Handler(sanitise=False, live_markup=True))}
    assert kinds and kinds == {"stored"}, kinds


def test_a_record_quoted_into_a_field_value_is_not_executable():
    """An input's ``value`` is text: keeping the tag there executes nothing.

    The page strips nothing and the tag is on the page, so a probe that only
    asked "is the tag there" would credit this sink and every payload written
    into it. What the probe has to answer is whether the record reached markup.
    """
    findings = _scan(_Handler(sanitise=False))
    assert {f.vulnerability_type for f in findings} == {"reflection"}, findings
    assert findings[0].evidence == "server_stored:not_executable"
