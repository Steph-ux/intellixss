"""The report names what the scan left on the target.

A writing scan that cleans up perfectly and says nothing still leaves the
operator guessing, and one that cannot clean up at all must say so loudly.
Both renderers are checked because they are separate code paths: the console
table and the HTML document.
"""

from intellixss.models import ScanResult
from intellixss.report.html_report import _cleanup_rows


def _row(**kw):
    base = {
        "surface": "stored:comment",
        "create_url": "https://t/post/comment",
        "method": "POST",
        "delete_url": "",
        "delete_method": "DELETE",
        "cleanable": True,
        "removed": 0,
        "reason": "",
    }
    base.update(kw)
    return base


def test_an_empty_cleanup_says_the_scan_wrote_nothing():
    out = _cleanup_rows([])
    assert "wrote nothing" in out


def test_a_removed_record_is_shown_as_removed():
    out = _cleanup_rows([_row(removed=1, delete_url="https://t/post/comment/1")])
    assert "<td>yes</td>" in out
    assert "could not be removed" not in out


def test_a_record_that_could_not_be_removed_is_called_out():
    out = _cleanup_rows([_row(removed=0, reason="the create response named no identifier")])
    assert "<td>no</td>" in out
    assert "1 record(s) could not be removed" in out


def test_the_count_that_could_not_be_removed_is_exact():
    rows = [
        _row(removed=1),
        _row(removed=0, reason="x"),
        _row(removed=0, reason="y"),
    ]
    assert "2 record(s) could not be removed" in _cleanup_rows(rows)


def test_the_json_report_carries_the_cleanup_rows():
    r = ScanResult(target_url="https://t/")
    r.cleanup = [_row(removed=1)]
    doc = r.to_dict()
    assert doc["cleanup"][0]["surface"] == "stored:comment"
