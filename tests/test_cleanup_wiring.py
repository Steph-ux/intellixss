"""The scan actually registers its writes, cleans them up and reports them.

The unit tests around ``cleanup`` pin the removal rules in isolation. These
pin the wiring, which is where a cleanup feature usually fails silently: the
plugin writes a record but nothing ever tells the orchestrator it exists, so
the report says "0 records" on a scan that left three comments behind.

Driving the real orchestrator against a local server is what proves the
registration happens at the write, not at the finding.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from intellixss.config import Config
from intellixss.scanner.orchestrator import Scanner
from intellixss.scanner.cleanup import delete_url_from_response

# A handler that stores a comment and names the record it made, the shape a
# modern JSON API returns. GET returns the last comment so the stored pass can
# re-render it.
STATE = {"comments": [], "deletes": []}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _html(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        listing = "".join(f"<p>{c}</p>" for c in STATE["comments"])
        self._html(f"<html><body><form action='/comment' method=post>"
                   f"<input name='text'><button>go</button></form>{listing}</body></html>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode()
        from urllib.parse import parse_qs
        value = (parse_qs(raw).get("text") or [""])[0]
        STATE["comments"].append(value)
        body = '{"id": %d}' % len(STATE["comments"])
        data = body.encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_DELETE(self):
        STATE["deletes"].append(self.path)
        self.send_response(204)
        self.end_headers()


@pytest.fixture()
def server():
    STATE["comments"].clear()
    STATE["deletes"].clear()
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _scan(url: str, writes: bool):
    cfg = Config(workers=1, rate_limit=40, timeout=5, retries=0, use_browser=False,
                 deep=False, max_payloads_per_param=2, writes=writes)
    return asyncio.run(Scanner(cfg).scan(url))


def test_a_writing_scan_registers_the_record_it_creates(server):
    result = _scan(server + "/", writes=True)
    assert STATE["comments"], "the scan did not write, so nothing was proven"
    assert result.cleanup, "a write happened but the run registered nothing"
    assert any(r["surface"].startswith("stored:") for r in result.cleanup)


def test_the_identifier_from_the_response_becomes_the_delete_url():
    url = delete_url_from_response("https://t/api/c", '{"id": 5}', {})
    assert url == "https://t/api/c/5"


def test_a_read_only_scan_creates_nothing_and_reports_no_cleanup(server):
    result = _scan(server + "/", writes=False)
    assert STATE["comments"] == []
    assert STATE["deletes"] == []
    assert result.cleanup == []
