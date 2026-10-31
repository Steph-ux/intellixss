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

from bs4 import BeautifulSoup

import intellixss.plugins.stored_xss as mod

MARKER = "ixpABC123"
# The probe's own text, derived the way the probe derives it, so a record quoted
# away from markup can be told apart from one that became an element.
WORD = f"ixp{hashlib.md5(MARKER.encode()).hexdigest()[:5]}"

SHIPPED = {}


def probes(page: str) -> bool:
    """Run the probe against *page*, which the render step hands back.

    Each ``{MARKER}`` in the page is the record's own name: the probe writes
    the marker and, right after it, ``w`` and the word's digits, and what the
    test hands back adds that trail so a kept element and a stripped record
    differ only in the element itself.
    """

    async def send(value: str):
        SHIPPED["value"] = value
        return 200, "", {}, ""

    original = mod._render_one

    async def render_one(_client, _url):
        # ``page`` says where the record is and what survived of it. The trail
        # the probe wrote for its own record is added after the marker, so a
        # page that kept the element and one that stripped it differ in the
        # element alone — the way the probe's own read-back does.
        text = page.replace(MARKER, f"{MARKER}w{SHIPPED['value'][-5:]}")
        return 200, text, {}

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
    """The bytes, with no element left: the page stripped it.

    The record is otherwise intact, trail and all; what it lost is the element,
    and that is the whole question a markup probe asks.
    """
    assert not probes(f"<p>{WORD}{MARKER}</p>")


def test_a_record_quoted_into_a_text_attribute_is_not_live():
    """An input's value is text, whatever tag the record contains."""
    assert not probes(f'<input type=text value="<b>{WORD}</b>{MARKER}">')


def test_the_record_written_into_an_image_source_is_not_live():
    """An ``img src`` is a URL the browser fetches, not markup it parses.

    Juice Shop's profile page puts the stored username there. Accepting it
    as markup kept a field live whose payload only becomes markup when the
    page hands it to the template, not when the browser loads the image.
    """
    assert not probes(f'<img src="<b>{WORD}</b>{MARKER}" alt="profile">')


def test_a_word_the_page_escaped_is_still_the_probe_word():
    """The word is looked for by shape, not by the bytes that were sent.

    An application that escapes the value on the way out writes a backslash
    where the probe wrote a letter — on the Juice Shop profile, before every
    letter of ``ixp``, and before the ``c`` of the digits. The element is there
    and the record is in it; reading the page by the exact bytes it was handed
    claimed the page stripped markup it kept, and every payload in that record
    was then refused. The escapes are written between the word's letters here,
    which is where the profile puts them.
    """
    escaped = WORD.replace("x", "\\x", 1)
    assert escaped != WORD
    assert mod._an_element_survives(
        f"<p><b>{escaped}</b>{MARKER}w{WORD[3:]}</p>", MARKER, escaped
    )


def test_a_record_on_the_page_is_read_by_its_own_word():
    """Two probes on one page write two words of the same shape.

    A field whose record is written second sits after the first one's markup,
    and matching whichever word comes first answered about the wrong record:
    the profile page failed the probe for its username because the image URL
    probed before it had left a word of its own further up the document.
    """
    first = "ixp0a1b2c"
    second = "ixp3d4e5f"
    first_marker = "ixpAAAAAAA"
    second_marker = "ixpBBBBBBB"
    page = (
        f"<p><b>{first}</b>{first_marker}</p>"
        f"<p><b>{second}</b>{second_marker}w{second[3:]}</p>"
    )
    assert mod._an_element_survives(page, second_marker, second)


def test_the_word_tag_inside_a_string_is_not_a_kept_tag():
    assert not probes(f'<script>var x = "<b>{WORD}</b>{MARKER}"</script>')


def test_src_is_markup_on_the_elements_that_parse_a_document():
    """The same attribute, two meanings, decided by the element.

    ``iframe src`` names a document the browser parses and ``srcdoc`` a string
    it parses, so both carry markup. Reading ``src`` as a URL everywhere would
    refuse a frame that renders the record; reading it as markup everywhere
    kept a profile picture's URL live.
    """

    def markup(name: str, tag_name: str) -> bool:
        soup = BeautifulSoup(f"<{tag_name} {name}=x>", "html.parser")
        return mod._read_as_markup(soup.find(True), name)

    assert markup("srcdoc", "iframe")
    assert markup("src", "iframe")
    assert markup("src", "frame")
    assert markup("src", "object")
    assert markup("style", "div")
    assert markup("href", "a")
    assert not markup("src", "img")
    assert not markup("src", "script")
    assert not markup("src", "video")
    assert not markup("title", "a")
    assert not markup("alt", "img")


def test_the_word_tag_in_an_attribute_is_not_a_kept_tag():
    """``title`` holds text; the record is shown as text beside it."""
    assert not probes(f'<a title="<b>{WORD}</b>{MARKER}">{WORD}{MARKER}</a>')


def test_a_page_without_the_record_says_nothing_either_way():
    """No record on the page: the probe cannot judge, so it keeps the claim."""
    assert probes("<p>nothing here</p>")


def test_a_page_that_did_not_load_says_nothing_either_way():
    """A 404 body says nothing about what the page does with markup.

    Reading it as "stripped" downgrades a field whose page simply was not
    reachable at that URL.
    """
    assert probes("Not Found")
