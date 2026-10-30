"""Parameters the page reads in script but never links to must still be found.

A page can read ``storeId`` straight out of ``URLSearchParams`` and never put it
in an ``href``. A link-only crawl then reports the page as having nothing to
inject into, while the page is in fact reading a parameter the attacker
controls — and passing it to ``document.write``.
"""

from intellixss.discovery.targets import _detect_client_query_params


def test_reads_url_search_params_object():
    html = (
        "var store = (new URLSearchParams(window.location.search)).get('storeId');"
    )
    assert _detect_client_query_params(html) == ["storeId"]


def test_reads_search_params_property():
    html = "const q = new URL(window.location).searchParams.get('search');"
    assert _detect_client_query_params(html) == ["search"]


def test_reads_from_a_stored_parser():
    """The page usually keeps the parser in a local before calling ``.get``."""
    html = (
        "var p = new URLSearchParams(window.location.search);"
        "var id = p.get('postId'); var tab = p.get('tab');"
    )
    assert _detect_client_query_params(html) == ["postId", "tab"]


def test_no_url_search_params_means_no_client_keys():
    """``.get('x')`` on a Map is not a query key, so nothing is invented."""
    html = "var m = new Map(); m.get('colour');"
    assert _detect_client_query_params(html) == []


def test_dynamic_keys_are_not_reported():
    html = (
        "var p = new URLSearchParams(location.search);"
        "for (var k of p.keys()) { var v = p.get(k); }"
    )
    # ``k`` names no literal parameter; reporting it would scan a value the
    # page never reads.
    assert _detect_client_query_params(html) == []


def test_duplicates_collapse():
    html = (
        "new URLSearchParams(a).get('storeId');"
        "new URLSearchParams(b).get('storeId');"
        "new URLSearchParams(c).get('other');"
    )
    assert _detect_client_query_params(html) == ["storeId", "other"]
