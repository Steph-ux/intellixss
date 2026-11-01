"""Blind delivery wiring, driven through the real orchestrator.

The unit tests pin payload shape; this pins that a ``--blind`` scan actually
sends those beacons into the discovered injection points, records each delivery
with its correlation marker, and — the honesty invariant — never turns a
delivery into a confirmed finding, because nothing here observed it fire.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

import pytest

from intellixss.config import Config
from intellixss.scanner.orchestrator import Scanner

# Everything the target received, so the test can assert a beacon arrived.
SEEN = {"queries": [], "headers": []}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = urlsplit(self.path).query
        SEEN["queries"].append(q)
        SEEN["headers"].append({k.lower(): v for k, v in self.headers.items()})
        # A static page that reflects nothing: keeps the test about blind
        # delivery, with no reflected finding to confuse the assertions.
        body = b"<!doctype html><html><body><p>static</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve():
    SEEN["queries"].clear()
    SEEN["headers"].clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run(url, cfg):
    return asyncio.run(Scanner(cfg).scan(url))


def test_blind_delivers_beacons_and_records_them():
    srv, base = _serve()
    try:
        cfg = Config(
            blind_url="oast.example",
            blind_header=True,
            use_browser=False,
            rate_limit=50,
        )
        result = _run(f"{base}/?q=1", cfg)
    finally:
        srv.shutdown()

    # Deliveries were recorded, each carrying a correlation marker and an
    # off-origin beacon URL that names the operator host.
    assert result.blind_deliveries, "expected recorded blind deliveries"
    param_deliveries = [d for d in result.blind_deliveries if d["via"] == "param"]
    assert any(d["parameter"] == "q" for d in param_deliveries)
    for d in result.blind_deliveries:
        assert d["marker"].startswith("ixm")
        assert "oast.example" in d["oob"]
        assert d["marker"] in d["oob"]

    # The target actually received a beacon in the ``q`` parameter: the payload
    # names the collaborator host and carries the recorded marker.
    q_marker = next(d["marker"] for d in param_deliveries if d["parameter"] == "q")
    got_param_beacon = any(
        "oast.example" in qs and q_marker in qs for qs in SEEN["queries"]
    )
    assert got_param_beacon

    # --blind-header delivered a beacon in a header too.
    header_deliveries = [d for d in result.blind_deliveries if d["via"] == "header"]
    assert header_deliveries
    hdr_values = " ".join(
        v for h in SEEN["headers"] for v in h.values()
    )
    assert "oast.example" in hdr_values

    # Honesty: a delivery is never a confirmed finding.
    assert result.confirmed == []
    for f in result.findings:
        assert f.verified_by != "blind"


def test_no_blind_pass_without_the_flag():
    srv, base = _serve()
    try:
        cfg = Config(use_browser=False, rate_limit=50)
        result = _run(f"{base}/?q=1", cfg)
    finally:
        srv.shutdown()
    assert result.blind_deliveries == []
    # No request carried an off-origin beacon.
    assert not any("oast.example" in qs for qs in SEEN["queries"])
