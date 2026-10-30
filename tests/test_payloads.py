"""Payload generation and mutation tests."""

from intellixss.models import CharProbeResult, FilterType, InjectionContext
from intellixss.payloads.generator import generate_payloads
from intellixss.payloads.mutations import apply_mutations, filter_by_char_survival, tab_bypass
from intellixss.payloads.waf_profiles import get_waf_payloads, profile_for_filters


def test_html_text_payloads_include_script_or_event():
    payloads = generate_payloads(InjectionContext.HTML_TEXT, limit=20)
    assert payloads
    joined = "\n".join(payloads).lower()
    assert "script" in joined or "onerror" in joined or "onload" in joined


def test_attr_double_breakout():
    payloads = generate_payloads(InjectionContext.HTML_ATTR_DOUBLE, limit=15)
    assert any(p.startswith('"') or "><" in p for p in payloads)


def test_strip_script_avoids_script_first():
    payloads = generate_payloads(
        InjectionContext.HTML_TEXT,
        filters=[FilterType.STRIP_SCRIPT],
        limit=15,
    )
    # Should still have img/svg alternatives
    assert any("img" in p.lower() or "svg" in p.lower() for p in payloads)


def test_sucuri_profile_payloads():
    assert profile_for_filters([FilterType.WAF_SUCURI]) == "sucuri"
    payloads = get_waf_payloads([FilterType.WAF_SUCURI])
    assert len(payloads) >= 3
    assert any("svg" in p.lower() or "img" in p.lower() for p in payloads)


def test_mutations_expand():
    base = "<img src=x onerror=alert(1)>"
    muts = apply_mutations(base, [FilterType.WAF_GENERIC])
    assert len(muts) > 1
    assert base in muts


def test_tab_bypass_changes_spaces():
    p = "<img src=x onerror=alert(1)>"
    t = tab_bypass(p)
    assert "\t" in t or t != p


def test_char_survival_filter_drops_angle_when_blocked():
    payloads = [
        "<script>alert(1)</script>",
        '"onmouseover="alert(1)',
        "javascript:alert(1)",
    ]
    kept = filter_by_char_survival(payloads, blocked={"<", ">"}, encoded=set(), min_keep=1)
    assert "<script>" not in "\n".join(kept) or '"onmouseover' in "\n".join(kept)
    assert any(p.startswith('"') or p.startswith("javascript:") for p in kept)


def test_generate_respects_char_probe():
    probe = CharProbeResult(
        param="q",
        reflected=True,
        allowed_chars={'"', "'", "="},
        blocked_chars={"<", ">"},
        encoded_chars={},
    )
    payloads = generate_payloads(
        InjectionContext.HTML_ATTR_DOUBLE,
        char_probe=probe,
        limit=10,
    )
    assert payloads  # still returns something


def test_unquoted_ranking_prefers_event_handlers():
    """First payloads for unquoted attrs must be real breakouts, not '-alert(1)-' noise."""
    payloads = generate_payloads(InjectionContext.HTML_ATTR_UNQUOTED, limit=8)
    assert payloads
    top = payloads[0]
    top_l = top.lower()
    assert "on" in top_l and "=" in top_l, f"expected event handler first, got {top!r}"
    # None of the first three should be bare alert-text noise
    for p in payloads[:3]:
        pl = p.lower().strip()
        assert not (
            "alert" in pl and "on" not in pl and "<" not in pl
        ), f"noise ranked too high: {p!r}"
    # Explicit preferred patterns appear early
    joined = "\n".join(payloads[:5]).lower()
    assert "onmouseover" in joined or "onfocus" in joined or "onerror" in joined


def test_unquoted_does_not_lead_with_quote_alert_noise():
    payloads = generate_payloads(InjectionContext.HTML_ATTR_UNQUOTED, limit=15)
    # If noise is present at all, it must not be index 0
    if any("'-alert" in p.lower() or "'-alert" in p for p in payloads):
        assert not payloads[0].lower().strip().startswith("'-")


def test_case_variation_preserves_alert():
    from intellixss.payloads.mutations import case_variation

    out = case_variation("<svg/onload=alert(1)>")
    assert "alert" in out
    assert "aLeRt" not in out and "AlErT" not in out


def test_html_text_prefers_executable_alert():
    payloads = generate_payloads(InjectionContext.HTML_TEXT, limit=5)
    # Top payloads should keep lowercase alert for browser execution
    top = "\n".join(payloads[:3])
    assert "alert(" in top or "alert`" in top
