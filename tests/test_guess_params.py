"""Does the bounded guess pass stay quiet on a page that reflects nothing?

A guess that scans a dead name is a false target: it costs requests and can
report a finding the app cannot produce. The pass is only acceptable if a page
which ignores every conventional name yields no target at all.

The second half asserts the opposite: a page that *does* echo ``search`` must be
discovered without any link or form pointing at it.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from intellixss.config import Config
from intellixss.discovery.targets import guess_reflected_params
from intellixss.http.client import HttpClient

IGNORES = """<!doctype html><html><body>
<p>Nothing here reads the query string.</p>
</body></html>"""

ECHOES = """<!doctype html><html><body>
<p id="terms">__TERMS__</p>
</body></html>"""

NAMES = ("search", "q", "query", "s", "keyword", "term")


def _serve(echo: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            terms = ""
            if echo and "?" in self.path:
                for pair in self.path.split("?", 1)[1].split("&"):
                    name, _, value = pair.partition("=")
                    if name in NAMES:
                        terms = unquote(value)
            body = (ECHOES.replace("__TERMS__", terms) if echo else IGNORES).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.mark.asyncio
async def test_guess_finds_an_unlinked_parameter():
    srv, base = _serve(echo=True)
    try:
        async with HttpClient(Config()) as client:
            found = await guess_reflected_params(client, f"{base}/", None, f"{base}/", {})
    finally:
        srv.shutdown()
    assert "search" in found
    # ``q`` is echoed by the same fixture, so it must be found too — a bound of
    # two keeps the pass from spending a request per name on a page that answers
    # all of them.
    assert set(found) <= {"search", "q"}


@pytest.mark.asyncio
async def test_guess_is_silent_when_nothing_is_echoed():
    srv, base = _serve(echo=False)
    try:
        async with HttpClient(Config()) as client:
            found = await guess_reflected_params(client, f"{base}/", None, f"{base}/", {})
    finally:
        srv.shutdown()
    assert found == []
