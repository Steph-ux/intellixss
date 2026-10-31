"""The browser confirmation a plugin asks for carries its own marker.

The engine proves execution by seeing *its* marker come back. The plugins used
to pass ``alert(1)``: no marker, so ``confirm`` accepted any dialog the page
happened to raise and the plugin credited it at 0.95 — the same number a causal
confirmation gets.

The contract pinned here is that every plugin builds its payload from a unique
marker, embeds it in the probe, and hands the same marker to ``confirm``. The
per-plugin tests below drive the real scan function against a scripted client
and assert what reached the browser, not what the scan concluded.
"""

import asyncio

import pytest

from intellixss.plugins import graphql_xss, json_xss, redirect_xss, upload_xss

MARKER_RE = __import__("re").compile(r"ixm[0-9a-f]{6,}")


class Recorder:
    """A browser double that records what each confirmation was asked to prove."""

    available = True

    def __init__(self, confirm=False):
        self.calls = []
        self._confirm = confirm

    async def confirm(self, url, *, payload="", marker="", **_kw):
        from intellixss.verify.browser import _extract_marker
        from intellixss.verify.browser import BrowserConfirmResult

        self.calls.append(
            {"url": url, "payload": payload, "marker": marker,
             "extracted": _extract_marker(payload)}
        )
        ok = self._confirm and bool(marker or _extract_marker(payload))
        return BrowserConfirmResult(ok, "stub")


def _marker_proved(call) -> bool:
    """True when the call could only ever be confirmed by its own marker."""
    return bool(call["marker"] or call["extracted"]) and "alert(1)" != call["payload"]


# ---------------------------------------------------------------- upload


class UploadClient:
    """Accepts the multipart write and answers with a URL for the stored file."""

    async def request(self, method, url, **_kw):
        return 201, '<a href="/files/xss.svg">stored</a>', {}, url


def test_upload_confirmation_carries_a_marker():
    browser = Recorder()
    asyncio.run(
        upload_xss.scan_upload_xss(
            UploadClient(),
            "https://t.test/",
            html='<form action="/upload" method="post"><input type="file" name="f"></form>',
            browser=browser,
        )
    )
    assert browser.calls, "upload must reach the browser confirmation"
    call = browser.calls[0]
    assert _marker_proved(call), call
    # The marker the caller declares is the one inside the payload, so the
    # engine cannot credit a dialog that some other request raised.
    assert call["marker"] in call["payload"] or call["extracted"] == call["marker"]


def test_upload_body_really_contains_the_marker():
    # The payload string and the bytes sent must agree: a scan that names a
    # marker the file does not contain would confirm its own bookkeeping.
    marker = "ixmdeadbeef"
    for filename, ctype, kind, content in upload_xss.upload_payloads(marker):
        assert marker.encode() in content, f"{kind} ({filename}) lost the marker"
        assert b"alert(1)" not in content, f"{kind} still carries a literal alert"


# ---------------------------------------------------------------- json


class JsonClient:
    """Reflects the injected field back inside an HTML document."""

    def __init__(self):
        self.sent = []

    async def inject_json(self, url, field, value, base=None, method="POST"):
        self.sent.append(value)
        return 200, f"<html><body>{value}</body></html>", {"Content-Type": "text/html"}, url

    async def request(self, method, url, **_kw):
        return 200, f"<html><body>{self.sent[-1] if self.sent else ''}</body></html>", {
            "Content-Type": "text/html"
        }, url


def test_json_confirmation_carries_a_marker():
    browser = Recorder()
    asyncio.run(
        json_xss.scan_json_xss(
            JsonClient(),
            "https://t.test/api",
            html='<script>fetch("/api/comment", {method:"POST"})</script>',
            browser=browser,
        )
    )
    assert browser.calls, "a reflected JSON body must be sent to the browser"
    assert _marker_proved(browser.calls[0]), browser.calls[0]


# ---------------------------------------------------------------- graphql


class GqlClient:
    def __init__(self):
        self.vars = []

    async def request(self, method, url, json_body=None, **_kw):
        if json_body and json_body.get("variables"):
            self.vars.append(json_body["variables"])
        if json_body and "__typename" in (json_body.get("query") or ""):
            return 200, '{"data":{"__typename":"Query"}}', {}, url
        # The mutation echoes the stored field on the base page.
        value = ""
        for v in (json_body or {}).get("variables", {}).values():
            value = v
        return 200, "<html>ok</html>", {}, url


class GqlStoringClient(GqlClient):
    async def request(self, method, url, json_body=None, **_kw):
        body = await super().request(method, url, json_body=json_body)
        if method == "GET":
            value = next(iter(self.vars[-1].values()), "") if self.vars else ""
            return 200, f"<html><body>{value}</body></html>", {}, url
        return body


def test_graphql_confirmation_carries_a_marker():
    browser = Recorder()
    asyncio.run(
        graphql_xss.scan_graphql_xss(
            GqlStoringClient(), "https://t.test/", browser=browser
        )
    )
    assert browser.calls, "a mutation whose record is on the page must be confirmed"
    assert _marker_proved(browser.calls[0]), browser.calls[0]


def test_graphql_mutation_sends_the_marker_not_a_literal_alert():
    client = GqlClient()
    asyncio.run(graphql_xss.scan_graphql_xss(client, "https://t.test/"))
    # A mutation template also carries identifiers it needs (``postId`` and
    # friends); only the values that are markup can be the injected payload,
    # and every one of those has to carry the marker.
    sent = [v for vars_ in client.vars for v in vars_.values() if isinstance(v, str) and "<" in v]
    assert sent, "the probe must actually mutate"
    assert all(MARKER_RE.search(v) for v in sent), sent
    assert not any("alert(1)" in v for v in sent)


# ---------------------------------------------------------------- redirect


class RedirectClient:
    def __init__(self):
        self.last = ""

    async def request(self, method, url, **_kw):
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(url).query)
        value = next((v[0] for v in q.values() if v), "")
        if value.startswith("javascript:"):
            value = value.replace("alert(1)", f"alert('{value.split('alert(')[1][:0]}')")
        self.last = value
        body = f'<a href="{value}">go</a>'
        return 200, body, {}, url


class MarkedRedirectClient:
    """Echoes the attacker value into an ``href``, as a real reflector would."""

    async def request(self, method, url, **_kw):
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(url).query)
        value = next((v[0] for v in q.values() if v), "")
        if "javascript:" in value.lower():
            return 200, f'<a href="{value}">go</a>', {}, url
        return 200, f"<html><body>{value}</body></html>", {}, url


def test_redirect_confirmation_carries_a_marker():
    browser = Recorder()
    asyncio.run(
        redirect_xss.scan_redirect_xss(MarkedRedirectClient(), "https://t.test/?next=1", browser=browser)
    )
    assert browser.calls, "a reflected javascript: value must be confirmed"
    assert _marker_proved(browser.calls[0]), browser.calls[0]
