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


def test_root_empty_path_and_slash_are_one():
    """``host?s=`` and ``host/?s=`` are the same endpoint — one finding.

    Observed against a live site: a DOM finding on ``s`` was reported twice,
    once with an empty path and once with ``/``. ``urlparse`` gives ``""`` and
    ``"/"`` respectively, so an un-normalised path keyed them apart.
    """
    a = _f(
        "https://isoceltelecom.com?s=javascript:alert('ixmaaa111')",
        "s",
        "javascript:alert('ixmaaa111')",
        vtype="dom",
    )
    b = _f(
        "https://isoceltelecom.com/?s=javascript:alert('ixmbbb222')",
        "s",
        "javascript:alert('ixmbbb222')",
        vtype="dom",
    )
    assert not _is_new_finding([a], b)
    assert len(_dedupe_findings([a, b])) == 1


def test_same_path_different_host_kept():
    """A path-only key would merge findings across hosts during a crawl."""
    a = _f("https://a.example.com/search?q=1", "q", "<svg/onload=alert(1)>")
    b = _f("https://b.example.com/search?q=1", "q", "<svg/onload=alert(1)>")
    assert _is_new_finding([a], b)
    assert len(_dedupe_findings([a, b])) == 2
