"""Cross-page stored XSS for the root-only stored-discovery benchmark.

The real shape of stored XSS: a comment is posted to /comment, the response
redirects to /thanks (Post/Redirect/Get — the payload is never echoed back),
and the record is rendered on a *different* page, /posts, linked from the
index. Finding it from the root means correlating "write here" with "renders
there" automatically — which a scanner with no stored workflow (XSStrike) and
one that scans a single URL (Dalfox without a trigger) cannot do.

Run: python bench/stored_range.py [port]   (default 8910)
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

STORE: list = []


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
        path = self.path.split("?")[0]
        if path == "/":
            self._send(_page(
                "<h1>Guestbook</h1>"
                "<form action='/comment' method='post'><input name='comment'>"
                "<button>Post</button></form> <a href='/posts'>See all posts</a>"
            ))
        elif path == "/thanks":
            self._send(_page("<p>Thanks, your post is pending.</p>"))
        elif path == "/posts":
            self._send(_page(
                "<h1>Posts</h1>"
                + "".join(f"<div class='post'>{c}</div>" for c in STORE)
            ))  # stored XSS sink
        else:
            self._send(b"not found", status=404)

    def do_POST(self):
        if self.path.split("?")[0] == "/comment":
            n = int(self.headers.get("Content-Length", 0) or 0)
            STORE.append(parse_qs(self.rfile.read(n).decode()).get("comment", [""])[0])
            self.send_response(303)
            self.send_header("Location", "/thanks")  # payload NOT echoed here
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(b"not found", status=404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8910
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"stored range on http://127.0.0.1:{port}  (post /comment -> renders /posts)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
