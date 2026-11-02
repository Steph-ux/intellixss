"""A payload a strict CSP blocks must not be reported as executed.

The element ``<svg onload=alert('marker')>`` is parsed into the DOM, so its
``onload`` attribute carries the marker whether or not the handler ran. Under
``script-src 'none'`` the handler never runs — a real browser does not fire it.
Crediting execution from the attribute's mere presence (its source) was a false
CONFIRMED; execution must be proven by a signal the handler emits (dialog /
console / off-origin request), which a strict CSP prevents. So the confirmer
must return not-confirmed here, while the same payload without CSP confirms.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit, parse_qs

import pytest

pytest.importorskip("playwright")

from intellixss.config import Config  # noqa: E402
from intellixss.verify.browser import BrowserConfirmer  # noqa: E402


def _make_handler(csp: str):
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<!doctype html><html><body><div>{unquote(q)}</div></body></html>".encode()
            self.send_response(200)
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


def _serve(csp: str):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(csp))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


async def _confirm(url: str, payload: str, marker: str) -> bool:
    confirmer = BrowserConfirmer(Config())
    await confirmer.start()
    try:
        r = await confirmer.confirm(
            url, context_hint="html_text", payload=payload, marker=marker,
            timeout_ms=4000,
        )
        return r.confirmed
    finally:
        await confirmer.stop()


@pytest.mark.asyncio
async def test_strict_csp_blocks_confirmation():
    marker = "ixmcsp0001"
    payload = f"<svg/onload=alert('{marker}')>"
    srv, base = _serve("default-src 'none'; script-src 'none'")
    try:
        confirmed = await _confirm(f"{base}/?q={quote(payload)}", payload, marker)
    finally:
        srv.shutdown()
    assert confirmed is False, "a CSP-blocked handler must not be confirmed"


@pytest.mark.asyncio
async def test_same_payload_without_csp_confirms():
    marker = "ixmcsp0002"
    payload = f"<svg/onload=alert('{marker}')>"
    srv, base = _serve("")  # no CSP
    try:
        confirmed = await _confirm(f"{base}/?q={quote(payload)}", payload, marker)
    finally:
        srv.shutdown()
    assert confirmed is True, "without CSP the same payload executes and confirms"
