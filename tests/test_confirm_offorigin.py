"""The browser confirmer's off-origin request evidence.

A payload that reaches ``x.src = '//ixm….example/x'`` proves it ran by asking
for that host. The proof is easy to fake by accident: the document URL carries
the payload, and the page's own analytics echo reflected values into same-origin
sub-resource URLs. Either one puts the marker on the wire without a single line
of the payload having executed, so both must be rejected.
"""

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote

import pytest

pytest.importorskip("playwright")

from intellixss.config import Config  # noqa: E402
from intellixss.verify.browser import BrowserConfirmer  # noqa: E402

PAGE = """<!doctype html><html><body>
<script>
  var searchTerms = '__TERMS__';
  document.write('<img src="/tracker.gif?q=' + encodeURIComponent(searchTerms) + '">');
</script>
</body></html>"""

# Escapes the quote the way the lab does: one backslash in front of it.
ESCAPER = re.compile(r"(['\"])")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        path = self.path
        terms = "hello"
        if "search=" in path:
            # Reflect the way a quote-escaping app does: the value is copied
            # verbatim, then each quote is given a backslash. A test page that
            # copies it raw models a *different* app, and would pass payloads
            # that this class of lab rejects.
            raw = unquote(path.split("search=", 1)[1].split("&")[0])
            terms = ESCAPER.sub(r"\\\1", raw)
        if path.startswith("/tracker.gif"):
            body = b"GIF89a"
            ctype = "image/gif"
        else:
            body = PAGE.replace("__TERMS__", terms).encode()
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()


@pytest.mark.asyncio
async def test_marker_in_document_url_is_not_execution(server):
    """A quoted value is echoed into the URL and the tracker, never executed."""
    confirmer = BrowserConfirmer(Config())
    await confirmer.start()
    try:
        payload = "';x=new Image;x.src=`//ixmctrl0001.ixm.example/x`//"
        result = await confirmer.confirm(
            f"{server.url}/?search={quote(payload)}",
            context_hint="js_string_single",
            payload=payload,
            marker="ixmctrl0001",
            timeout_ms=4000,
        )
    finally:
        await confirmer.stop()

    assert result.confirmed is False


@pytest.mark.asyncio
async def test_offorigin_request_confirms_execution(server):
    """The same shape, unquoted, builds the URL from code that ran.

    The reflected value only ever contains the marker; the host is completed by
    ``.ixm.example`` in the code, so no request to it can come from the URL the
    browser was sent to.
    """
    confirmer = BrowserConfirmer(Config())
    await confirmer.start()
    try:
        payload = "\\';x=new Image;x.src=`//ixmlive0001`+`.ixm.example/x`;//"
        result = await confirmer.confirm(
            f"{server.url}/?search={quote(payload)}",
            context_hint="js_code",
            payload=payload,
            marker="ixmlive0001",
            timeout_ms=4000,
        )
    finally:
        await confirmer.stop()

    assert result.confirmed is True
    assert "ixmlive0001.ixm.example" in result.detail
    assert result.marker_echoed is True
