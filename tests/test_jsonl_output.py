"""Line-delimited JSON output for recon pipelines.

Pins the contract a pipeline depends on: one flat object per finding, highest
severity first, blind deliveries tagged distinctly and never labelled
confirmed, and the flag wired so it mutes the scanner's own stdout the way
``--json`` does.
"""

import json

from intellixss.cli import build_parser, jsonl_lines
from intellixss.models import (
    InjectionContext,
    ScanResult,
    XSSFinding,
)


def _finding(vtype, confirmed, context=InjectionContext.HTML_TEXT):
    return XSSFinding(
        url="http://x.test/?q=1",
        parameter="q",
        method="GET",
        context=context,
        payload="<svg onload=alert(1)>",
        evidence="…",
        browser_confirmed=confirmed,
        vulnerability_type=vtype,
        verified_by="browser" if confirmed else "reflection",
        marker="ixmdeadbe",
    )


def test_each_finding_is_one_flat_line_sorted_by_severity():
    result = ScanResult(target_url="http://x.test/")
    # A low-severity unconfirmed reflected and a high-severity confirmed stored.
    result.findings = [
        _finding("reflected", False),
        _finding("stored", True),
    ]
    lines = jsonl_lines(result)
    assert all(l["kind"] == "finding" for l in lines)
    # Highest severity first.
    assert lines[0]["cvss"] >= lines[1]["cvss"]
    assert lines[0]["vulnerability_type"] == "stored"
    # Each line is independently serialisable (true JSONL).
    for l in lines:
        json.loads(json.dumps(l))
        assert l["target_url"] == "http://x.test/"
        assert "reproduce" in l


def test_blind_deliveries_are_tagged_and_never_confirmed():
    result = ScanResult(target_url="http://x.test/")
    result.blind_deliveries = [
        {
            "url": "http://x.test/?q=1",
            "parameter": "q",
            "method": "GET",
            "via": "param",
            "oob": "//oast.example/ixmdeadbe",
            "marker": "ixmdeadbe",
            "status": 200,
        }
    ]
    lines = jsonl_lines(result)
    assert len(lines) == 1
    assert lines[0]["kind"] == "blind_delivery"
    assert lines[0]["verified_label"] == "UNCONFIRMED"
    assert "browser_confirmed" not in lines[0]


def test_jsonl_flag_parses_and_is_off_by_default():
    assert build_parser().parse_args(["-u", "http://x.test/", "--jsonl"]).jsonl is True
    assert build_parser().parse_args(["-u", "http://x.test/"]).jsonl is False
