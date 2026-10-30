"""Stored sinks: the payload family follows where the echo lands, not the field.

A form field is not a sink. ``website`` comes back inside ``<a href="…">`` and
a markup payload is inert there, while ``comment`` comes back as escaped text
and no payload at all can run. Both decisions are made from the observed echo,
so these tests drive ``scan_server_stored`` against a scripted client.
"""

from intellixss.models import InjectionContext
from intellixss.plugins.stored_xss import _build_payloads, scan_server_stored


class FakeClient:
    """Replays a fixed render body and records every injected value.

    ``form_html`` is what the form's own page serves: it decides both whether
    the write is located elsewhere and whether the field only accepts a link.
    """

    def __init__(
        self,
        render_body: str,
        holder: str = "value",
        form_html: str = "<html><body>no form</body></html>",
    ):
        self.render_body = render_body
        self.holder = holder
        self.form_html = form_html
        self.sent = []
        self.value = ""

    async def inject(self, url, param, value, method="POST", base_data=None, **_kw):
        self.sent.append((param, value))
        self.value = value
        return 200, "<html>ok</html>", {}, url

    async def request(self, method, url, **_kw):
        # The form lives on the page that carries it; the handler is a bare
        # endpoint and answers with nothing a browser could execute. The page
        # renders whatever the last submission stored.
        if url.startswith("https://t.test/post?"):
            if self.value:
                return 200, self.render_body.replace("{V}", self.value), {}, url
            return 200, self.form_html, {}, url
        if "confirmation" in url:
            return 200, "<html><body>Comment submitted</body></html>", {}, url
        return 200, "<html>ok</html>", {}, url


PAGE = "<html><body><a id=author href=\"{V}\">n</a></body></html>"
FORM = (
    "<html><body><form action=\"/post?postId=1\" method=\"POST\">"
    "<input name=\"website\" pattern=\"(http:|https:).+\" type=\"text\">"
    "</form></body></html>"
)


async def test_href_sink_gets_url_payloads():
    client = FakeClient(PAGE, form_html=FORM)
    findings = await scan_server_stored(
        client,
        "https://t.test/post/comment",
        field="website",
        base_data={"comment": "x"},
        render_urls=["https://t.test/post?postId=1"],
        max_payloads=4,
    )
    payloads = [v for _p, v in client.sent if v.startswith(("javascript:", "data:"))]
    assert payloads, client.sent
    # The handler lives on its own endpoint, so the response it returns is not
    # the record's page: the value is only "stored" once the article shows it,
    # and the reconciliation endpoint is what serves that page.
    assert findings, "an href echo of a resurrected value is a stored sink"


async def test_link_shaped_field_is_wrapped_past_its_validator():
    """A field that only accepts a link still reaches the sink behind it.

    The validator rejects the bare value with ``400``; the URL shape the field
    declares carries it to the sink verbatim, so the field is tested instead of
    being written off as unreachable.
    """

    class Validated(FakeClient):
        async def inject(self, url, param, value, method="POST", base_data=None, **_kw):
            self.sent.append((param, value))
            self.value = value
            if not value.startswith(("http://", "https://")):
                return 400, "Invalid website", {}, url
            return 200, "<html>ok</html>", {}, url

    client = Validated(PAGE, form_html=FORM)
    await scan_server_stored(
        client,
        "https://t.test/post/comment",
        field="website",
        base_data={"comment": "x"},
        render_urls=["https://t.test/post?postId=1"],
        max_payloads=2,
    )
    assert any(v.startswith("http://ixv.example/") for _p, v in client.sent), client.sent


async def test_escaped_echo_is_not_a_stored_sink():
    escaped = (
        "<html><body><a href=\"http://example.com\">n</a>"
        "<p>&lt;img src=x onerror=alert(1)&gt;</p></body></html>"
    )

    class EscapedClient(FakeClient):
        async def request(self, method, url, **_kw):
            return 200, escaped.replace("alert(1)", "alert('IXM')"), {}, url

    client = EscapedClient(escaped)
    findings = await scan_server_stored(
        client,
        "https://t.test/post/comment",
        field="comment",
        render_urls=["https://t.test/post?postId=1"],
    )
    assert findings == []


def test_attr_sink_payloads_avoid_markup():
    payloads = _build_payloads("ixm1234abcd", 4, InjectionContext.HTML_ATTR_HREF)
    assert payloads[0].startswith("javascript:")
    assert not any("<" in p for p in payloads[:2])
