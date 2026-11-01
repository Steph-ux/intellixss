"""A small, self-contained XSS range for a fair three-way benchmark.

Every scanner under test (IntelliXSS, Dalfox, XSStrike) is pointed at this one
server, so the comparison is on identical ground. Endpoints fall in two groups:

* **vulnerable** — a real, exploitable reflection in a named context. A scanner
  that reports the ``q`` parameter here scores a true positive.
* **clean** — the value is reflected safely (escaped) or not at all. A scanner
  that reports ``q`` here scores a false positive. These are what separate a
  precise tool from one that flags every reflection.

The contexts are the ones all three tools claim to handle (HTML text, quoted /
unquoted attributes, a JS string, a tag-blocking filter, and a query-driven
DOM sink), chosen to be representative rather than tuned to any one scanner.

Run directly: ``python bench/range.py [port]`` (default 8799).
"""

from __future__ import annotations

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# name -> (is_vulnerable, context label, html template using {q})
#
# Templates insert the raw parameter where marked. For clean endpoints the
# value is escaped (or dropped) before it reaches the template.
ENDPOINTS = {
    # --- vulnerable ---
    "reflect_html": (True, "html_text", "<div>{q}</div>"),
    "reflect_attr": (True, "attr_double", '<input type=text value="{q}">'),
    "reflect_attr_sq": (True, "attr_single", "<input type=text value='{q}'>"),
    "reflect_unquoted": (True, "attr_unquoted", "<input type=text value={q}>"),
    "reflect_js": (True, "js_string", "<script>var a='{q}';</script>"),
    "reflect_filtered": (True, "html_text_filtered", "<div>{q}</div>"),  # strips <script
    "dom_query": (True, "dom_query", (
        "<div id=o></div><script>"
        "document.getElementById('o').innerHTML="
        "new URLSearchParams(location.search).get('q');"
        "</script>"
    )),
    # --- vulnerable, harder (tests filter-bypass depth) ---
    # Blocks the two most common tags; a scanner must reach for another.
    "hard_tag_block": (True, "html_text_tagblock", "<div>{q}</div>"),
    # Double-quoted attribute where the quote survives but the three most common
    # event handlers are stripped; a scanner must find another event/attribute.
    "hard_attr_events": (True, "attr_double_eventblock", '<input value="{q}">'),

    # --- clean controls (reflection without exploitability — FP traps) ---
    "safe_escaped": (False, "html_text_escaped", "<div>{q}</div>"),
    "safe_attr_escaped": (False, "attr_double_escaped", '<input value="{q}">'),
    "safe_noreflect": (False, "no_reflection", "<div>static</div>"),
    # Reflects raw in HTML text but strips every "<": no tag can form, so the
    # reflection is not exploitable. Catches reflection-only scanners.
    "trap_text_no_lt": (False, "html_text_no_lt", "<div>{q}</div>"),
    # Inside a double-quoted attribute, only the quote is escaped. "<" and ">"
    # pass, but with no way to close the attribute the value cannot break out.
    "trap_attr_quote_only": (False, "attr_double_quote_escaped", '<input value="{q}">'),
    # Inside a JS string where quote, backslash and "<" are all neutralised: the
    # string cannot be closed and <script> cannot be ended. Not exploitable.
    "trap_js_escaped": (False, "js_string_escaped", "<script>var a=\"{q}\";</script>"),
}

PAGE = "<!doctype html><html><head><title>range</title></head><body>{inner}</body></html>"


def render(name: str, q: str) -> str:
    vuln, _ctx, tmpl = ENDPOINTS[name]
    if name == "safe_noreflect":
        inner = tmpl
    elif name == "safe_escaped":
        inner = tmpl.format(q=html.escape(q))
    elif name == "safe_attr_escaped":
        inner = tmpl.format(q=html.escape(q, quote=True))
    elif name == "reflect_filtered":
        # A naive tag filter: drops the literal "<script" (any case) but leaves
        # every other tag — the classic bypassable blocklist.
        import re

        inner = tmpl.format(q=re.sub(r"<script", "", q, flags=re.I))
    elif name == "hard_tag_block":
        # Blocks <script and <svg; <img>/<body> events still get through.
        import re

        inner = tmpl.format(q=re.sub(r"<\s*(script|svg)", "", q, flags=re.I))
    elif name == "hard_attr_events":
        # Quote survives; the three most common handlers are stripped. A break-
        # out still works with another event/attribute (autofocus+onfocus, …).
        import re

        inner = tmpl.format(q=re.sub(r"on(error|load|mouseover)", "", q, flags=re.I))
    elif name == "trap_text_no_lt":
        inner = tmpl.format(q=q.replace("<", ""))
    elif name == "trap_attr_quote_only":
        inner = tmpl.format(q=q.replace('"', "&quot;"))
    elif name == "trap_js_escaped":
        safe = q.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\x3c")
        inner = tmpl.format(q=safe)
    else:
        inner = tmpl.format(q=q)
    return PAGE.format(inner=inner)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        name = parts.path.strip("/") or "index"
        if name == "index":
            links = "".join(
                f'<a href="/{n}?q=1">{n}</a><br>' for n in ENDPOINTS
            )
            body = PAGE.format(inner=links).encode()
            self._send(body)
            return
        if name not in ENDPOINTS:
            self._send(b"not found", status=404)
            return
        q = parse_qs(parts.query).get("q", [""])[0]
        self._send(render(name, q).encode())

    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"range on http://127.0.0.1:{port}  ({len(ENDPOINTS)} endpoints)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
