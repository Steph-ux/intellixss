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
    # The fixture echoes any of the conventional names; the pass must surface at
    # least the canonical ``search`` without a link or form pointing at it, and
    # every name it returns must be one the fixture actually echoes (never a
    # guess that did not reflect).
    assert "search" in found
    assert set(found) <= set(NAMES)


@pytest.mark.asyncio
async def test_guess_is_silent_when_nothing_is_echoed():
    srv, base = _serve(echo=False)
    try:
        async with HttpClient(Config()) as client:
            found = await guess_reflected_params(client, f"{base}/", None, f"{base}/", {})
    finally:
        srv.shutdown()
    assert found == []


# --- mining reach: a name no dictionary carries, read only from the page ---

# The page reveals a bespoke parameter through its own JS, and the handler
# echoes it. No static wordlist would ever guess ``xyzzyReflect``; mining the
# page is the only way to reach it. This is the capability that finds
# parameters a dictionary-only miner (Dalfox/Arjun's default) cannot.
MINED = """<!doctype html><html><body>
<div id="out">__OUT__</div>
<script>
  var p = new URLSearchParams(location.search);
  document.getElementById('out').textContent = p.get('xyzzyReflect');
</script>
</body></html>"""


def _serve_named(echoes):
    """Serve a page whose handler echoes exactly the parameter names in *echoes*."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            out = ""
            if "?" in self.path:
                for pair in self.path.split("?", 1)[1].split("&"):
                    name, _, value = pair.partition("=")
                    if name in echoes:
                        out = unquote(value)
            body = MINED.replace("__OUT__", out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.mark.asyncio
async def test_mining_reaches_a_name_no_dictionary_has():
    srv, base = _serve_named({"xyzzyReflect"})
    try:
        async with HttpClient(Config()) as client:
            # The baseline body (served to the miner) carries the JS read, so
            # the name is mined from the page and then proven with the canary.
            _, body, _, _ = await client.request("GET", f"{base}/")
            found = await guess_reflected_params(
                client, f"{base}/", None, f"{base}/", {f"{base}/": body}
            )
    finally:
        srv.shutdown()
    assert found == ["xyzzyReflect"]


@pytest.mark.asyncio
async def test_aggressive_lifts_the_default_hit_cap():
    # Four conventional names all echo. The default pass stops at its hit cap;
    # ``--aggressive`` keeps going and surfaces every injectable parameter.
    echoes = {"search", "query", "message", "redirect"}
    srv, base = _serve_named(echoes)
    try:
        async with HttpClient(Config()) as client:
            _, body, _, _ = await client.request("GET", f"{base}/")
            pages = {f"{base}/": body}
            default = await guess_reflected_params(
                client, f"{base}/", None, f"{base}/", pages, Config(aggressive=False)
            )
            aggressive = await guess_reflected_params(
                client, f"{base}/", None, f"{base}/", pages, Config(aggressive=True)
            )
    finally:
        srv.shutdown()
    assert len(default) <= 3
    assert echoes <= set(aggressive)
