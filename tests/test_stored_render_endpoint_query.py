"""An endpoint the page names is read with the query it was asked for.

A comment thread is not in the document: the shell names its endpoint —
``loadComments('/post/comment')`` — and the script asks for the article's
records. Reading that endpoint without the article id returns 404, the record
looks like it was never stored, and a stored XSS that is on the page is reported
as absent.

The page's query is not a universal suffix, either. A paginated search endpoint
named with a query of its own asks for something else entirely when the page's
is appended, and the server answers 400. What the endpoint already says about
its parameters wins; what it leaves open is filled from the page.
"""

from __future__ import annotations

import asyncio

import intellixss.plugins.stored_xss as mod


class _Client:
    def __init__(self, bodies: dict) -> None:
        self.bodies = bodies
        self.asked: list[str] = []

    async def request(self, method, url, **kw):
        self.asked.append(url)
        return 200, self.bodies.get(url, ""), {}, url


PAGE = "http://lab.test/post?postId=9"


def test_a_bare_endpoint_is_read_for_the_article_the_page_names():
    out = asyncio.run(
        mod._render_endpoints(_Client({}), PAGE, "<script>loadComments('/post/comment')</script>")
    )
    assert "http://lab.test/post/comment?postId=9" in out, out


def test_an_endpoint_that_names_its_own_query_keeps_it():
    out = asyncio.run(
        mod._render_endpoints(
            _Client({}),
            "http://lab.test/rest/products/search?q=app",
            "<script>fetch('/post/comment?postId=3')</script>",
        )
    )
    assert "http://lab.test/post/comment?postId=3" in out, out
    assert all(u.count("?") <= 1 for u in out), out


def test_a_fetch_call_is_an_endpoint_like_an_xhr_open():
    out = asyncio.run(
        mod._render_endpoints(_Client({}), PAGE, "<script>fetch('/api/comments')</script>")
    )
    assert any("/api/comments" in u for u in out), out


def test_an_endpoint_without_a_page_query_is_left_alone():
    out = asyncio.run(
        mod._render_endpoints(
            _Client({}), "http://lab.test/index", "<script>loadComments('/post/comment')</script>"
        )
    )
    assert "http://lab.test/post/comment" in out, out
