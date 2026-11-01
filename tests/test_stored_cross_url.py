"""Stored XSS that surfaces on a different page from the one that takes it.

A comment posted to /comment appears on /posts — the real shape of stored XSS,
where the write endpoint and the render page differ (Post/Redirect/Get, the
payload never echoed in the POST response). The stored pass must look for its
marker on the pages the site links to, not only on the form's own page. This is
what a tool with no cross-endpoint workflow (XSStrike) and one needing an
explicit trigger URL (Dalfox) cannot do automatically.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest

from intellixss.config import Config
from intellixss.http.client import HttpClient
from intellixss.plugins.stored_xss import scan_server_stored
from intellixss.scanner.orchestrator import Scanner

STORE = []


class _Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, b):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._html(
                b"<!doctype html><html><body>"
                b"<form action=/comment method=post><input name=comment></form>"
                b"<a href=/posts>posts</a></body></html>"
            )
        elif p == "/posts":
            body = "".join(f"<div class=post>{c}</div>" for c in STORE)
            self._html(f"<!doctype html><html><body>{body}</body></html>".encode())
        else:  # /thanks and everything else: no payload here
            self._html(b"<!doctype html><html><body>thanks</body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        STORE.append(parse_qs(self.rfile.read(n).decode()).get("comment", [""])[0])
        self.send_response(303)
        self.send_header("Location", "/thanks")  # redirect away from the render page
        self.send_header("Content-Length", "0")
        self.end_headers()


def _serve():
    STORE.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_render_pages_collects_linked_same_origin_pages():
    """The helper surfaces /posts (a link) as a candidate render page."""
    sc = Scanner(Config())
    body = (
        "<form action=/comment method=post><input name=comment></form>"
        "<a href='/posts'>posts</a><a href='http://evil.test/x'>off</a>"
        "<img src='/logo.png'>"
    )
    pages = sc._stored_render_pages("http://site.test/", body, [])
    assert "http://site.test/posts" in pages
    assert not any("evil.test" in p for p in pages)  # same-origin only
    assert not any(p.endswith(".png") for p in pages)  # no subresources


@pytest.mark.asyncio
async def test_stored_payload_is_found_on_a_different_render_page():
    srv, base = _serve()
    try:
        async with HttpClient(Config(writes=True)) as c:
            findings = await scan_server_stored(
                c,
                f"{base}/comment",
                field="comment",
                method="POST",
                base_data={},
                # /posts is the linked render page; the write endpoint and the
                # seed do not show the record.
                render_urls=[f"{base}/comment", f"{base}/", f"{base}/posts"],
                browser=None,
                log=lambda *a, **k: None,
            )
    finally:
        srv.shutdown()
    assert findings, "stored XSS on a different render page must be detected"
    f = findings[0]
    assert f.vulnerability_type == "stored"
    assert "/posts" in f.url
    # A real breakout payload, not just the canary.
    assert "onerror" in f.payload or "<" in f.payload
