"""A page that keeps the record's element proves markup survives, whatever it writes.

The stored pass writes a harmless ``<b>ixp</b><marker>`` and reads the page to
learn whether a tag survives at all. A page that re-serialises the record is
free to answer with another formatting element — ``strong`` for the ``b`` it was
given, an attribute the editor added, the tag moved inside a wrapper. Looking
for the tag it was handed back byte for byte reads a kept element as a stripped
one, the scan then believes every payload in that record is inert, and a fully
executable stored XSS is reported as a plain reflection that never runs.

What the probe asked was whether an element reached the parser. Any element
next to the record's own marker answers that, not only the one it sent.
"""

from __future__ import annotations

import asyncio
import hashlib

import intellixss.plugins.stored_xss as mod

MARKER = "ixpABC123"
# The probe's own text, derived the same way the probe derives it, so a record
# quoted away from markup can be told apart from one that became an element.
WORD = f"ixp{hashlib.md5(MARKER.encode()).hexdigest()[:6]}"

SHIPPED = {}


def probes(page: str) -> bool:
    """Run the probe against *page*, which the render step hands back."""

    async def send(value: str):
        SHIPPED["value"] = value
        return 200, "", {}, ""

    async def render_one(_client, _url):
        return 200, page, {}

    original = mod._render_one
    mod._render_one = render_one
    try:
        return asyncio.run(
            mod._markup_reaches_the_page(
                None,
                "http://t/post",
                field="comment",
                method="POST",
                send=send,
                data={},
                log=lambda *a, **k: None,
                marker=MARKER,
            )
        )
    finally:
        mod._render_one = original


def test_the_tag_it_sent_is_kept():
    assert probes(f"<p><b>{WORD}</b>{MARKER}</p>")


def test_a_rewritten_tag_is_still_a_kept_tag():
    """An editor that answers ``strong`` for ``b`` kept the element."""
    assert probes(f"<p><strong>{WORD}</strong>{MARKER}</p>")


def test_a_tag_carrying_an_extra_attribute_is_kept():
    assert probes(f'<p><b class="x">{WORD}</b>{MARKER}</p>')


def test_a_tag_the_page_wraps_is_still_kept():
    assert probes(f"<div class=record><code>{WORD}</code><span>{MARKER}</span></div>")


def test_a_record_in_an_attribute_the_browser_parses_as_markup_is_kept():
    """``srcdoc`` is markup read later; no element is built at parse time."""
    assert probes(f'<iframe srcdoc="<b>{WORD}</b>{MARKER}"></iframe>')


def test_a_stripped_record_is_not_a_kept_tag():
    """The bytes, with no element left: the page stripped it."""
    assert not probes(f"<p>{WORD}{MARKER}</p>")


def test_a_record_quoted_into_a_text_attribute_is_not_live():
    """An input's value is text, whatever tag the record contains."""
    assert not probes(f'<input type=text value="<b>{WORD}</b>{MARKER}">')


def test_the_word_tag_inside_a_string_is_not_a_kept_tag():
    assert not probes(f'<script>var x = "<b>{WORD}</b>{MARKER}"</script>')


def test_the_word_tag_in_an_attribute_is_not_a_kept_tag():
    assert not probes(f'<a title="<b>{WORD}</b>{MARKER}">{WORD}{MARKER}</a>')


def test_a_page_without_the_record_says_nothing_either_way():
    """No record on the page: the probe cannot judge, so it keeps the claim."""
    assert probes("<p>nothing here</p>")
