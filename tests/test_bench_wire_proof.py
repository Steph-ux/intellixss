"""A surface is credited only when its value can be shown reaching the server.

The browser can confirm a payload executes in a scan the harness fabricated:
a route with no request behind it, a header nothing forwards. The replay is
what separates "the scanner saw its payload run" from "the application gave
the scanner a place to put it", and a route whose value never leaves the
fragment has no wire proof at all.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))

import juice


def test_a_route_without_a_replay_is_not_replayed():
    surface = {"key": "tracking", "page": "/#/track", "route": "/track", "field": "id"}
    finding = {
        "method": "GET",
        "url": "http://t.test/#/track?id=1",
        "param": "id",
        "payload": "'><img src=x onerror=alert(1)>",
        "marker": "ixm1234abcd",
    }
    out = juice.reproduce("http://t.test", surface, finding, "", {})
    assert out["replayed"] is False
    assert out["note"].startswith("no wire request is known")


def test_a_route_with_a_replay_still_goes_to_the_wire():
    """The guard must not swallow the routes that do have a request."""
    surface = {
        "key": "tracking",
        "page": "/#/track",
        "route": "/track",
        "field": "id",
        "replay": "/rest/track-order/:id",
    }
    finding = {
        "method": "GET",
        "url": "http://t.test/#/track?id=1",
        "param": "id",
        "payload": "1",
        "marker": "ixm1234abcd",
    }
    seen = {}

    def fake_request(base, path, method, body, token, form=False):
        seen["path"] = path
        return 200, '{"order":"ixm1234abcd"}', {}

    original = juice.request
    juice.request = fake_request
    try:
        out = juice.reproduce("http://t.test", surface, finding, "", {})
    finally:
        juice.request = original
    assert seen["path"] == "/rest/track-order/1"
    assert out["echoed"] is True
