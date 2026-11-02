"""A reflection a strict CSP blocks is a lead, not a reported vulnerability.

Every reflected XSS finding needs inline execution — a tag's script, an event
handler, a ``javascript:`` URL. A page served with a strict CSP
(``script-src 'none'``) blocks all of those, so a reflection the scanner could
not run there is not exploitable as it stands. The orchestrator reclassifies
such a reflection-level finding to a CSP-blocked *diagnosis* (never silently
dropped), and leaves a reflection on a page without CSP a finding. This is the
precision a scanner that reads the response's CSP has and a character-survival
tool (no browser, no CSP awareness) does not.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

from intellixss.config import Config
from intellixss.scanner.orchestrator import Scanner


def _make(csp: str, header: str = "Content-Security-Policy"):
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            q = unquote(parse_qs(urlsplit(self.path).query).get("q", [""])[0])
            body = f"<!doctype html><html><body><div>{q}</div></body></html>".encode()
            self.send_response(200)
            if csp:
                self.send_header(header, csp)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


def _serve(csp: str, header: str = "Content-Security-Policy"):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make(csp, header))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _scan(url: str):
    # No browser: findings are reflection-level, which is exactly the class the
    # CSP reclassification governs — keeps the test fast and deterministic.
    return asyncio.run(Scanner(Config(use_browser=False)).scan(url))


def test_strict_csp_reflection_is_reclassified_not_reported():
    srv, base = _serve("default-src 'none'; script-src 'none'")
    try:
        result = _scan(f"{base}/?q=1")
    finally:
        srv.shutdown()
    assert result.findings == [], "a CSP-blocked reflection must not be a reported finding"
    assert any("csp-strict" in (d.signals or []) for d in result.diagnoses), \
        "it must be kept as a CSP-blocked diagnosis, not dropped"


def test_reflection_without_csp_is_still_a_finding():
    srv, base = _serve("")  # no CSP
    try:
        result = _scan(f"{base}/?q=1")
    finally:
        srv.shutdown()
    assert result.findings, "a reflection with no CSP must still be reported"


def test_report_only_csp_does_not_reclassify():
    """A strict policy sent *Report-Only* blocks nothing, so the reflection
    stays a finding — reclassifying it would hide a real XSS behind a policy
    that only reports violations."""
    srv, base = _serve(
        "default-src 'none'; script-src 'none'",
        header="Content-Security-Policy-Report-Only",
    )
    try:
        result = _scan(f"{base}/?q=1")
    finally:
        srv.shutdown()
    assert result.findings, (
        "a Report-Only CSP enforces nothing — the reflection must still be reported"
    )
    assert not any("csp-strict" in (d.signals or []) for d in result.diagnoses)


def test_reclassified_diagnosis_names_the_directive():
    srv, base = _serve("script-src 'self' https://cdn.example.com")
    try:
        result = _scan(f"{base}/?q=1")
    finally:
        srv.shutdown()
    assert result.findings == []
    csp_diag = [d for d in result.diagnoses if "csp-strict" in (d.signals or [])]
    assert csp_diag, "a strict script-src must reclassify the reflection"
    assert "cdn.example.com" in csp_diag[0].detail, (
        "the diagnosis must name the enforcing script-src so a reviewer can "
        "look for an allowlisted-origin bypass"
    )
