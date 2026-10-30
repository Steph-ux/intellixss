"""Finding deduplication helpers."""

from intellixss.models import InjectionContext, XSSFinding
from intellixss.scanner.orchestrator import _dedupe_findings, _is_new_finding


def _f(url, param, payload, vtype="reflected"):
    return XSSFinding(
        url=url,
        parameter=param,
        method="GET",
        context=InjectionContext.HTML_TEXT,
        payload=payload,
        evidence="e",
        vulnerability_type=vtype,
    )


def test_dedupe_same_payload_path():
    a = _f(
        "https://xss-game.appspot.com/level1/frame?query=x",
        "query",
        "<svg/onload=alert(1)>",
    )
    b = _f(
        "https://xss-game.appspot.com/level1/frame?query=y",
        "query",
        "<svg/onload=alert(1)>",
    )
    assert not _is_new_finding([a], b)
    out = _dedupe_findings([a, b, a])
    assert len(out) == 1


def test_different_params_kept():
    a = _f("https://x/level1/frame", "query", "p1")
    b = _f("https://x/level4/frame", "timer", "p2")
    assert _is_new_finding([a], b)
    assert len(_dedupe_findings([a, b])) == 2
