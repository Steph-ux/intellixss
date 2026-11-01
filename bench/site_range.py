"""Unified realistic site for the root-only "whole site" benchmark.

One root, several XSS behind it — the real task a scanner faces when handed a
URL rather than a list of exact injection points:

  /search?q=            reflected, param revealed by a link on /about
  /products?category=   reflected, param revealed by the link on /
  /feedback?comment=    reflected, behind a GET form two hops from the root
  POST /comment -> /posts   stored: posted via the form on /board, redirects to
                            /thanks (never echoed), renders on /posts

Every scanner is given only `http://host/`. Finding these means crawling and,
for the stored one, correlating a write with a render on another page.

Run: python bench/site_range.py [port]   (default 8920)
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

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
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            self._send(_page(
                "<h1>Home</h1>"
                "<a href='/about'>About</a> "
                "<a href='/products?category=electronics'>Products</a> "
                "<a href='/board'>Guestbook</a>"
            ))
        elif u.path == "/about":
            self._send(_page(
                "<p>About.</p> <a href='/search?q=hello'>search</a> "
                "<a href='/feedback'>feedback</a>"
            ))
        elif u.path == "/search":
            self._send(_page(f"<div>{q.get('q', [''])[0]}</div>"))  # reflected XSS
        elif u.path == "/products":
            self._send(_page(f"<div>{q.get('category', [''])[0]}</div>"))  # reflected XSS
        elif u.path == "/feedback":
            if "comment" in q:
                self._send(_page(f"<div>{q.get('comment', [''])[0]}</div>"))  # reflected XSS
            else:
                self._send(_page(
                    "<form action='/feedback' method='get'><input name='comment'></form>"
                ))
        elif u.path == "/board":
            self._send(_page(
                "<form action='/comment' method='post'><input name='comment'>"
                "<button>Post</button></form> <a href='/posts'>See posts</a>"
            ))
        elif u.path == "/thanks":
            self._send(_page("<p>Thanks.</p>"))
        elif u.path == "/posts":
            self._send(_page(
                "".join(f"<div class='post'>{c}</div>" for c in STORE)
            ))  # stored XSS sink
        else:
            self._send(b"not found", status=404)

    def do_POST(self):
        if self.path.split("?")[0] == "/comment":
            n = int(self.headers.get("Content-Length", 0) or 0)
            STORE.append(parse_qs(self.rfile.read(n).decode()).get("comment", [""])[0])
            self.send_response(303)
            self.send_header("Location", "/thanks")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(b"not found", status=404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8920
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"site range on http://127.0.0.1:{port}  (4 XSS behind the root)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
