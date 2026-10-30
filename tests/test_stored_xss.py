"""Stored XSS plugin unit tests (pure + structure)."""

from intellixss.plugins.stored_xss import STORED_PAYLOADS, STORE_FIELDS
from intellixss.models import XSSFinding, InjectionContext


def test_stored_payloads_are_executable_shape():
    assert any("onerror" in p or "onload" in p for p in STORED_PAYLOADS)
    assert all("alert" in p for p in STORED_PAYLOADS)


def test_store_fields_include_content():
    assert "content" in STORE_FIELDS
    assert "message" in STORE_FIELDS


def test_stored_finding_model():
    f = XSSFinding(
        url="https://x/level2/frame",
        parameter="content",
        method="CLIENT",
        context=InjectionContext.HTML_TEXT,
        payload="<img src=x onerror=alert(1)>",
        evidence="client_stored_form",
        browser_confirmed=True,
        vulnerability_type="stored_client",
    )
    d = f.to_dict()
    assert d["browser_confirmed"] is True
    assert d["vulnerability_type"] == "stored_client"
