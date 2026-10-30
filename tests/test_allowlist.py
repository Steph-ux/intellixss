"""Allowlist discovery: ask the target which markup it accepts, then use it.

The generator's payload bank covers two worlds — everything reflects, or
characters are encoded. A filter that keeps ``<math>`` while dropping ``<img>``
and its whole event-handler blocklist is neither, and no fixed payload can be
right about it. These tests pin the learning step: tags are probed one by one
and the *first survivor* is the one the payload is built from, so the answer
comes from the target rather than from a list of guesses.
"""

import asyncio
from html import escape

from intellixss.models import CharProbeResult, ContextAnalysis, InjectionContext
from intellixss.scanner.orchestrator import (
    _EVENT_CANDIDATES,
    _TAG_CANDIDATES,
    _allowlist_payloads,
)


def _ctx(context=InjectionContext.HTML_TEXT, quote_char=""):
    return ContextAnalysis(
        context=context,
        quote_char=quote_char,
        char_probe=CharProbeResult(param="search", reflected=True),
    )


class FilteringClient:
    """Accepts a fixed set of tags and a fixed set of handlers."""

    def __init__(self, tags, handlers):
        self.tags = set(tags)
        self.handlers = set(handlers)
        self.sent = []

    async def inject(self, url, param, value, method="POST", base_data=None, **kw):
        self.sent.append(value)
        for tag in self.tags:
            if f"<{tag}" in value and f"</{tag}>" in value:
                return 200, value, {}, url
        for handler in self.handlers:
            if handler in value:
                return 200, value, {}, url
        if "<" in value:
            # Rejected the way a blocklist does: the request fails outright.
            return 400, "", {}, url
        return 200, value, {}, url


async def _learn(client, param="search"):
    """Drive the tag/handler probes the way the orchestrator does."""
    for name in _TAG_CANDIDATES:
        probe = f"<{name} ixptag=1>x</{name}>"
        st, body, _h, _f = await client.inject("u", param, probe)
        if st == 200 and probe in body:
            tag = name
            break
    else:
        return "", ""

    for event in _EVENT_CANDIDATES:
        probe = f"<{tag} ixp{param} {event}=alert(1)>"
        st, body, _h, _f = await client.inject("u", param, probe)
        if st == 200 and probe in body:
            return tag, event
    return tag, ""


def test_learns_the_tag_the_filter_permits():
    client = FilteringClient(tags=["math"], handlers=["onbeforetoggle"])
    tag, event = asyncio.run(_learn(client))
    assert tag == "math", [v for v in client.sent if "ixptag" in v]
    assert event == "onbeforetoggle"


def test_no_allowlist_when_characters_are_encoded():
    class EncodingClient:
        async def inject(self, url, param, value, method="POST", base_data=None, **kw):
            return 200, f"<h1>{escape(value)}</h1>", {}, url

    tag, event = asyncio.run(_learn(EncodingClient()))
    assert tag == "" and event == ""


def test_payload_uses_the_learned_pair_not_a_fixed_one():
    payloads = _allowlist_payloads("xss", "onbeforetoggle", "ixm0a1b2c3d", _ctx())
    assert payloads, "no payload built for a learned pair"
    assert any("onbeforetoggle" in p for p in payloads)
    assert all("ixm0a1b2c3d" in p for p in payloads), "marker missing — unverifiable"
    # A popover handler runs only while the element is being shown, so at
    # least one candidate has to make it a popover or the handler is dead code.
    assert any("popover" in p for p in payloads[:3])


def test_payload_closes_the_attribute_it_lands_in():
    ctx = _ctx(InjectionContext.HTML_ATTR_DOUBLE, quote_char='"')
    payloads = _allowlist_payloads("xss", "onfocus", "ixm0a1b2c3d", ctx)
    assert payloads[0].startswith('"'), payloads[0]
