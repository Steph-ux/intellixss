"""A bench surface is credited by the sink it names, not by any sink it scans.

Every surface points the scanner at the same page, so one scan reports every
sink the bundle exposes. The grade for ``#/privacy-security/last-login-ip`` must
come from that route, not from the search box a few lines above it, and the
grade for a review API must not come from a complaint API that happens to share
a field name.
"""

import bench.juice as bench

BASE = "http://127.0.0.1:3000"


def surface(key: str) -> dict:
    return {s["key"]: s for s in bench.SURFACES}[key]


def finding(param: str, url: str, payload: str = "", method: str = "POST") -> dict:
    return {
        "param": param,
        "url": url,
        "payload": payload,
        "marker": "ixm00000000",
        "method": method,
    }


def test_a_browser_owned_source_is_credited_to_the_route_it_renders_on():
    # The finding names ``localStorage``, not the surface's header field: a
    # source is not a parameter of the endpoint, and the sink it reaches is
    # exactly the one the surface is about.
    assert bench._on_sink(
        surface("last-login-ip"), finding("localStorage", f"{BASE}/#/privacy-security/last-login-ip")
    )


def test_another_route_is_another_sink():
    # ``q`` confirms on ``#/search`` during every scan; that says nothing about
    # the last-login-ip component.
    for other in ("#/search?q=x", "#/track-result?id=x", "#/403?error=x"):
        assert not bench._on_sink(surface("last-login-ip"), finding("q", f"{BASE}/{other}"))


def test_another_field_of_the_same_route_is_another_sink():
    assert bench._on_sink(surface("profile"), finding("username", f"{BASE}/profile"))
    assert not bench._on_sink(surface("profile"), finding("imageUrl", f"{BASE}/profile"))


def test_another_handler_with_the_same_field_name_is_not_credited():
    assert bench._on_sink(surface("reviews"), finding("message", f"{BASE}/rest/products/1/reviews"))
    assert not bench._on_sink(surface("reviews"), finding("message", f"{BASE}/api/Complaints"))
    assert bench._on_sink(surface("complaints"), finding("message", f"{BASE}/api/Complaints"))


def test_an_endpoint_surface_ignores_hash_route_findings():
    # A DOM sink found while scanning a form surface is a real finding, but it
    # belongs to no challenge on that surface.
    assert not bench._on_sink(surface("reviews"), finding("localStorage", f"{BASE}/#/search"))


def test_a_profile_replay_sends_the_field_the_finding_names():
    # The profile form has an image URL field, and the model treats an empty
    # value there as "no image" — which lets the role setter overwrite the
    # admin's picture and makes the write fail. A replay must carry the field
    # under test and the identity's own email, nothing the page would not send.
    payload = "<img src=x onerror=alert('ixm0000d3e8')>"
    body = bench._form_body("profile", payload, {"email": "replay@bench.invalid"})
    assert body == {"username": payload, "email": "replay@bench.invalid"}


def test_a_replay_never_claims_a_sink_it_could_not_write():
    # Each surface the replay knows how to rebuild names the field it writes.
    # A surface without one must be reported as unreplayed rather than sent on
    # a guessed shape.
    for key in ("reviews", "feedback", "complaints", "login", "profile"):
        assert bench._form_body(key, "x", {}) is not None, key
    assert bench._form_body("home", "x", {}) is None


def test_a_server_rendered_form_is_posted_as_a_form_with_the_session_cookie():
    # ``/profile`` is a Pug page: it reads ``req.cookies.token`` and parses
    # urlencoded fields. Sending the JSON body and bearer header the API
    # surfaces use makes the write fail for a reason the application never
    # caused, and the replay then reports a defect that is the harness's.
    seen = []

    def fake(base, path, method="GET", body=None, token="", form=False, cookie=""):
        seen.append({"method": method, "body": body, "form": form, "cookie": cookie})
        return 200, "ok", {}

    original = bench.request
    bench.request = fake
    try:
        bench.reproduce(
            BASE,
            surface("profile"),
            finding("username", f"{BASE}/profile", "<img src=x onerror=alert('ixm1')>"),
            "jwt",
            {"email": "replay@bench.invalid"},
        )
    finally:
        bench.request = original
    write = [c for c in seen if c["method"] == "POST"]
    assert len(write) == 1, seen
    assert write[0]["form"] is True
    assert write[0]["cookie"] == "token=jwt"
    assert write[0]["body"] == {
        "username": "<img src=x onerror=alert('ixm1')>",
        "email": "replay@bench.invalid",
    }
    # Reading the record back is a GET on the same session, not a second write.
    assert [c["method"] for c in seen if c is not write[0]] == ["GET"]


def test_an_api_surface_is_still_posted_as_json():
    seen = []

    def fake(base, path, method="GET", body=None, token="", form=False, cookie=""):
        seen.append({"method": method, "form": form, "cookie": cookie})
        return 200, "ok", {}

    original = bench.request
    bench.request = fake
    try:
        bench.reproduce(
            BASE,
            surface("complaints"),
            finding("message", f"{BASE}/api/Complaints", "<img src=x onerror=alert('ixm2')>"),
            "jwt",
        )
    finally:
        bench.request = original
    assert seen, "nothing was sent"
    assert seen[0]["form"] is False
    assert seen[0]["cookie"] == ""


def test_the_tracking_route_is_its_own_surface():
    """The route a payload travels in is graded on the field it renders."""
    track = surface("track")
    assert bench._on_sink(track, finding("id", f"{BASE}/#/track-result?id=x", method="GET"))
    # ``q`` on the search box is a different component, and ``id`` anywhere
    # else is a different route or a different sink.
    assert not bench._on_sink(track, finding("q", f"{BASE}/#/search?q=x", method="GET"))
    assert not bench._on_sink(track, finding("id", f"{BASE}/?id=x", method="GET"))


def test_a_hash_route_without_a_replay_shape_stays_browser_only():
    finding_ = finding("id", f"{BASE}/#/track-result?id=x", payload="<img src=x onerror=alert(`ixm00000000`)>", method="GET")
    out = bench.reproduce(BASE, {"key": "track", "field": "id"}, finding_, "")
    assert out["dom"] is True
    assert out["status"] == 0
    assert "browser-only" in out["note"]
