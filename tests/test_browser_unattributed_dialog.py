"""A dialog that does not show our marker is still proof when the page got the payload.

The tracking route of a shop stores the id it is given and re-renders it through
a live sink, so the dialog prints the decoded value rather than the marker. The
confirmer used to require the marker in the dialog text and reported the sink as
``no_execution_observed``. These tests pin both halves of the rule: a dialog the
payload caused is accepted, a page that opens dialogs by itself is not.
"""

import asyncio

import pytest

from intellixss.config import Config
from intellixss.verify.browser import PLAYWRIGHT_AVAILABLE, BrowserConfirmer

pytestmark = pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright not installed")


PAGE_WITH_SINK = """<!doctype html><html><body>
<div id="out"></div>
<script>
  var id = new URLSearchParams(location.search).get('id') || '';
  document.getElementById('out').innerHTML = '<code>' + id + '</code>';
</script>
</body></html>"""


PAGE_THAT_PROMPTS = """<!doctype html><html><body>
<script>alert('welcome');</script>
</body></html>"""


async def _serve(html):
    """Serve *html* on a throwaway port. Returns (url, shutdown)."""
    body = html.encode()

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def shutdown():
        server.close()
        await server.wait_closed()

    return f"http://127.0.0.1:{port}", shutdown


def test_dialog_without_marker_counts_when_the_page_got_the_payload():
    async def run():
        url, shutdown = await _serve(PAGE_WITH_SINK)
        confirmer = BrowserConfirmer(Config(use_browser=True))
        await confirmer.start()
        try:
            # The marker is a substring of the payload that the sink splits
            # apart, so it never reaches the dialog text.
            result = await confirmer.confirm(
                url + "/?id=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
                payload="<img src=x onerror=alert(1)>",
                marker="onerror",
            )
        finally:
            await confirmer.stop()
            await shutdown()
        return result

    result = asyncio.run(run())
    assert result.confirmed is True
    assert result.detail == "dialog_unattributed"
    assert result.dialog_message == "1"
    # The marker itself was not seen, so the result must not claim it was.
    assert result.marker_echoed is False


def test_page_dialog_is_not_credited_when_the_payload_never_arrived():
    async def run():
        url, shutdown = await _serve(PAGE_THAT_PROMPTS)
        confirmer = BrowserConfirmer(Config(use_browser=True))
        await confirmer.start()
        try:
            result = await confirmer.confirm(
                url + "/",
                payload="<img src=x onerror=alert(1)>",
                marker="ixm0a1b2c3d",
            )
        finally:
            await confirmer.stop()
            await shutdown()
        return result

    result = asyncio.run(run())
    assert result.confirmed is False
    assert result.detail == "no_execution_observed"
