"""`analyze_csp` must distinguish an enforced policy from a Report-Only one.

A ``Content-Security-Policy-Report-Only`` header reports violations to an
endpoint but blocks nothing, so it can never be used to call a finding
CSP-mitigated. ``enforced_strict`` is the property the scanner gates on.
"""

from intellixss.analysis.filters import analyze_csp


def test_enforced_strict_policy():
    csp = analyze_csp({"Content-Security-Policy": "default-src 'none'; script-src 'none'"})
    assert csp is not None
    assert csp.present and csp.strict
    assert not csp.report_only
    assert csp.enforced_strict
    assert csp.effective_script_src == "'none'"


def test_report_only_strict_is_not_enforced():
    csp = analyze_csp(
        {"Content-Security-Policy-Report-Only": "default-src 'none'; script-src 'none'"}
    )
    assert csp is not None
    assert csp.strict  # the policy *is* strict in shape
    assert csp.report_only
    assert not csp.enforced_strict  # ...but it enforces nothing


def test_enforced_wins_when_both_present():
    csp = analyze_csp(
        {
            "Content-Security-Policy": "script-src 'self' https://cdn.example.com",
            "Content-Security-Policy-Report-Only": "script-src 'unsafe-inline'",
        }
    )
    assert csp is not None
    assert not csp.report_only
    assert csp.enforced_strict
    assert "cdn.example.com" in csp.effective_script_src


def test_unsafe_inline_is_not_strict():
    csp = analyze_csp({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})
    assert csp is not None
    assert not csp.strict
    assert not csp.enforced_strict


def test_no_csp_is_none():
    assert analyze_csp({}) is None
    assert analyze_csp({"X-Frame-Options": "DENY"}) is None
