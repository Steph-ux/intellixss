"""--crawl follows same-origin links and scans each page's own inputs.

Given only a site root, the default path-scoped discovery sees the seed's forms
and the links that already carry a query — not a form or a ``?q=`` that lives on
a page reachable only by following a link. The crawl closes that: it fetches the
linked pages and extracts their inputs too. This is the coverage a one-URL scan
never reaches.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from intellixss.config import Config
from intellixss.discovery.targets import discover_targets
from intellixss.http.client import HttpClient


class _Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _h(self, b):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlsplit(self.path).path
        if p == "/":
            self._h(b"<html><body><a href=/about>about</a> <a href=/search>search</a></body></html>")
        elif p == "/about":
            # A deep page whose own form is two hops from the root.
            self._h(b"<html><body><form action=/contact method=post><input name=message></form></body></html>")
        elif p == "/search":
            self._h(b"<html><body><a href='/search?q=hi'>q</a></body></html>")
        else:
            self._h(b"<html><body>x</body></html>")


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _urls(targets):
    return {urlsplit(t.url).path for t in targets}


@pytest.mark.asyncio
async def test_without_crawl_deep_pages_are_not_discovered():
    srv, base = _serve()
    try:
        async with HttpClient(Config()) as c:
            targets = await discover_targets(c, f"{base}/", Config(crawl=False))
    finally:
        srv.shutdown()
    paths = _urls(targets)
    # The root links to /search and /about but neither's inputs are reached.
    assert "/search" not in paths
    assert "/contact" not in paths


@pytest.mark.asyncio
async def test_crawl_discovers_inputs_on_linked_pages():
    srv, base = _serve()
    try:
        async with HttpClient(Config(crawl=True, writes=True)) as c:
            targets = await discover_targets(
                c, f"{base}/", Config(crawl=True, writes=True, max_crawl_depth=2)
            )
    finally:
        srv.shutdown()
    paths = _urls(targets)
    # The ?q= on /search (one hop) and the form posting to /contact (the form
    # lives on /about, two hops) are both discovered by following links.
    assert "/search" in paths
    assert "/contact" in paths
    # Same-origin only: nothing off-site leaked in.
    assert all("127.0.0.1" in t.url for t in targets)


@pytest.mark.asyncio
async def test_crawl_collects_pages_without_params_for_stored_render():
    """A crawled page with no parameter of its own is still collected.

    A stored record renders on such a page (a /posts listing), so the stored
    pass needs it as a render candidate even though it is not an injectable
    target itself. ``pages_out`` captures every crawled page for that purpose.
    """

    class _StoredSite(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _h(self, b):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            p = urlsplit(self.path).path
            if p == "/":
                self._h(b"<html><body><a href=/posts>posts</a></body></html>")
            else:  # /posts has no parameter of its own
                self._h(b"<html><body><div>listing</div></body></html>")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StoredSite)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    pages: set = set()
    try:
        async with HttpClient(Config(crawl=True)) as c:
            await discover_targets(c, f"{base}/", Config(crawl=True), pages_out=pages)
    finally:
        srv.shutdown()
    assert any(u.rstrip("/").endswith("/posts") for u in pages)
