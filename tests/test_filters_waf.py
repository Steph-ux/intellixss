"""WAF / filter classification tests."""

from pathlib import Path

from intellixss.analysis.filters import classify_filters, detect_waf
from intellixss.models import BlockReason, FilterType

FIXTURES = Path(__file__).parent / "fixtures"


def test_sucuri_body_fingerprint():
    body = (FIXTURES / "waf_sucuri_block.html").read_text(encoding="utf-8")
    filters, name, signals = detect_waf({"server": "Sucuri/Cloudproxy"}, body, 403)
    assert FilterType.WAF_SUCURI in filters
    assert name == "sucuri"
    assert signals


def test_cloudflare_header():
    filters, name, signals = detect_waf(
        {"cf-ray": "abc123", "server": "cloudflare"},
        "Attention Required! | Cloudflare",
        403,
    )
    assert FilterType.WAF_CLOUDFLARE in filters
    assert name == "cloudflare"


def test_html_encode_filter():
    marker = "abcXYZ"
    body = f"<div>{__import__('html').escape('<' + marker + '>')}</div>"
    # marker itself not present raw
    filters, diag = classify_filters(body, "<" + marker + ">", status=200)
    assert FilterType.HTML_ENCODE in filters or diag.reason in (
        BlockReason.CHAR_ENCODED,
        BlockReason.NO_REFLECTION,
        BlockReason.CHAR_STRIPPED,
    )


def test_no_filter_when_raw_marker():
    marker = "rawCanary99"
    body = f"<p>hello {marker} world</p>"
    filters, diag = classify_filters(body, marker, status=200)
    assert FilterType.NO_FILTER in filters
    assert diag.reason == BlockReason.NONE


def test_classify_waf_block_page():
    body = (FIXTURES / "waf_sucuri_block.html").read_text(encoding="utf-8")
    filters, diag = classify_filters(
        body, "test", headers={"x-sucuri-id": "1"}, status=403
    )
    assert FilterType.WAF_SUCURI in filters
    assert diag.reason in (BlockReason.WAF_PAGE, BlockReason.HTTP_STATUS)
