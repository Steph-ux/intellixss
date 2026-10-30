"""Stored sinks: the payload family follows where the echo lands, not the field.

A form field is not a sink. ``website`` comes back inside ``<a href="…">`` and
a markup payload is inert there, while ``comment`` comes back as escaped text
and no payload at all can run. Both decisions are made from the observed echo,
so these tests drive ``scan_server_stored`` against a scripted client.
"""

import json

from intellixss.models import InjectionContext
from intellixss.plugins import stored_xss
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


async def test_json_body_is_sent_as_json_not_form_fields():
    """A bundle-discovered API parses JSON; form fields answer ``400``.

    ``PUT /rest/products/:id/reviews`` reads ``{"message": …}``. Sending it
    ``message=…`` as form data is a request the handler rejects for its shape,
    and the field would then be recorded as unreachable on a target that
    stores it.
    """

    class JsonClient:
        def __init__(self):
            self.json_calls = []
            self.form_calls = []

        async def inject(self, url, param, value, method="POST", base_data=None, **_kw):
            self.form_calls.append((param, value))
            return 400, "{}", {}, url

        async def inject_json(self, url, field, value, base=None, method="POST"):
            self.json_calls.append((method, field, value))
            body = {"data": [{"message": value}]}
            return 200, json.dumps(body), {}, url

        async def request(self, method, url, **_kw):
            return 200, json.dumps({"data": [{"id": 1}]}), {}, url

    client = JsonClient()
    await scan_server_stored(
        client,
        "https://t.test/rest/products/1/reviews",
        field="message",
        method="PUT",
        base_data={"message": "test"},
        render_urls=["https://t.test/api/Products/1/"],
        json_body=True,
        max_payloads=2,
    )
    assert client.form_calls == []
    assert client.json_calls and client.json_calls[0][0] == "PUT"


async def test_a_write_reached_by_put_is_scanned_for_storage():
    """``PUT`` stores a record just as a form ``POST`` does.

    The stored pass used to keep only ``POST`` targets, which silently dropped
    every review-style sink an API exposes through ``PUT``/``PATCH``.
    """
    from types import SimpleNamespace

    from intellixss.models import ScanTarget
    from intellixss.plugins.stored_xss import scan_stored_auto
    from intellixss.plugins.stored_xss import scan_stored_auto

    seen = []

    async def fake_scan(client, url, *, field, method="POST", **_kw):
        seen.append((method, url, field))
        return []

    orig = stored_xss.scan_server_stored
    stored_xss.scan_server_stored = fake_scan
    try:
        targets = [
            ScanTarget(
                url="https://t.test/rest/products/1/reviews",
                method="PUT",
                params=["message"],
                data={"message": "test"},
                source="js_write",
            )
        ]
        await scan_stored_auto(
            SimpleNamespace(), "https://t.test/", targets=targets
        )
    finally:
        stored_xss.scan_server_stored = orig
    assert ("PUT", "https://t.test/rest/products/1/reviews", "message") in seen


def _finding(url: str, param: str) -> "XSSFinding":
    from intellixss.models import XSSFinding

    return XSSFinding(
        url=url,
        parameter=param,
        method="POST",
        context=InjectionContext.HTML_TEXT,
        payload="<img src=x onerror=alert('ixm00000000')>",
        evidence="stored",
        vulnerability_type="stored",
        verified_by="browser",
        marker="ixm00000000",
    )


async def test_a_client_side_finding_does_not_hide_the_bundle_targets():
    """One sink found on the page must not end the pass.

    The browser stage drives the SPA and stores a record in whatever form the
    page renders; that used to ``return`` from ``scan_stored_auto``, so the
    write targets read out of the bundle — the review ``PUT`` among them —
    were never tested at all. A site with two stored sinks reported one.
    """
    from types import SimpleNamespace

    from intellixss.models import ScanTarget
    from intellixss.plugins.stored_xss import scan_stored_auto

    page_finding = _finding("https://t.test/api/Complaints", "message")
    seen = []

    async def fake_client_stored(browser, url, **_kw):
        return [page_finding]

    async def fake_server(client, url, *, field, method="POST", **_kw):
        seen.append((method, url, field))
        return [_finding(url, field)]

    async def no_roundtrip(browser, url, **_kw):
        return []

    async def no_render(client, url, **_kw):
        return ""

    saved = (
        stored_xss.scan_client_stored,
        stored_xss.scan_store_roundtrip,
        stored_xss._store_render_url,
        stored_xss.scan_server_stored,
    )
    stored_xss.scan_client_stored = fake_client_stored
    stored_xss.scan_store_roundtrip = no_roundtrip
    stored_xss._store_render_url = no_render
    stored_xss.scan_server_stored = fake_server
    try:
        findings = await scan_stored_auto(
            SimpleNamespace(),
            "https://t.test/",
            browser=SimpleNamespace(available=True),
            targets=[
                ScanTarget(
                    url="https://t.test/rest/products/1/reviews",
                    method="PUT",
                    params=["message"],
                    data={"message": "test"},
                    source="js_write",
                )
            ],
        )
    finally:
        (
            stored_xss.scan_client_stored,
            stored_xss.scan_store_roundtrip,
            stored_xss._store_render_url,
            stored_xss.scan_server_stored,
        ) = saved

    assert seen == [("PUT", "https://t.test/rest/products/1/reviews", "message")]
    assert len(findings) == 2, findings


async def test_every_write_target_with_a_sink_is_reported():
    """Two writable endpoints, two findings — not just the first one.

    The target loop also returned on the first hit, so a scan that reached a
    complaints API stopped before the review API behind it.
    """
    from types import SimpleNamespace

    from intellixss.models import ScanTarget
    from intellixss.plugins.stored_xss import scan_stored_auto

    async def fake_server(client, url, *, field, method="POST", **_kw):
        return [_finding(url, field)]

    async def no_client(browser, url, **_kw):
        return []

    async def no_roundtrip(browser, url, **_kw):
        return []

    async def no_render(client, url, **_kw):
        return ""

    saved = (
        stored_xss.scan_client_stored,
        stored_xss.scan_store_roundtrip,
        stored_xss._store_render_url,
        stored_xss.scan_server_stored,
    )
    stored_xss.scan_client_stored = no_client
    stored_xss.scan_store_roundtrip = no_roundtrip
    stored_xss._store_render_url = no_render
    stored_xss.scan_server_stored = fake_server
    try:
        findings = await scan_stored_auto(
            SimpleNamespace(),
            "https://t.test/",
            targets=[
                ScanTarget(
                    url="https://t.test/api/Complaints",
                    method="POST",
                    params=["message"],
                    data={"message": "test"},
                    source="js_write",
                ),
                ScanTarget(
                    url="https://t.test/rest/products/1/reviews",
                    method="PUT",
                    params=["message"],
                    data={"message": "test"},
                    source="js_write",
                ),
            ],
        )
    finally:
        (
            stored_xss.scan_client_stored,
            stored_xss.scan_store_roundtrip,
            stored_xss._store_render_url,
            stored_xss.scan_server_stored,
        ) = saved

    assert {f.url for f in findings} == {
        "https://t.test/api/Complaints",
        "https://t.test/rest/products/1/reviews",
    }
