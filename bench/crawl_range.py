"""Multi-page site for the root-only discovery benchmark.

The reflected XSS lives on /search?q= — a GET search box reachable only by
following a link from the index, the shape a real site takes. A scanner given
only the root has to *crawl* to reach it; one that scans a single URL, or whose
crawler only looks for forms, never sees it.

Run: python bench/crawl_range.py [port]   (default 8890)
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


def _page(inner: str) -> bytes:
    return f"<!doctype html><html><body>{inner}</body></html>".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/":
            self._send(_page(
                "<h1>Home</h1><a href='/about'>About</a> "
                "<a href='/search'>Search</a>"
            ))
        elif u.path == "/about":
            self._send(_page("<p>About us.</p> <a href='/search?q=hello'>search hello</a>"))
        elif u.path == "/search":
            q = parse_qs(u.query).get("q", [""])[0]
            self._send(_page(f"<h1>Results</h1><div>{q}</div>"))  # reflected XSS
        else:
            self._send(b"not found", status=404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8890
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"crawl range on http://127.0.0.1:{port}  (XSS at /search?q=, linked from /)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
