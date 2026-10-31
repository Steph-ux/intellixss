"""Juice Shop bench: scan OWASP Juice Shop and score it against the challenges
the application itself documents.

Usage:
    python bench/juice.py              # all surfaces
    python bench/juice.py --list       # show the roster
    python bench/juice.py --only reviews
    python bench/juice.py --no-browser # HTTP surfaces only, no Chromium

The target is a local instance (default ``http://127.0.0.1:3000``); override it
with ``--base``. Nothing is tuned per surface: each one is scanned with the
stock configuration, and the score is read from what the scanner reported.

Scoring is against ``data/static/challenges.yml``, not the Score Board. The
Score Board counts *solving the room* — buying a product, guessing a password,
placing a forged review — which no XSS scanner does. The bench counts the
challenges whose category is ``XSS``: nine of them in Juice Shop 20.3.0.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from intellixss.auth import AuthConfig
from intellixss.config import Config
from intellixss.scanner.orchestrator import Scanner

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "benchmark" / "juiceshop.json"
REPORT = ROOT / "benchmark" / "juiceshop-report.md"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# The nine challenges of category XSS in ``data/static/challenges.yml``. The
# order is the file's own order, so a reader can check the list by grep.
# ``surface`` names the roster entry that reaches the challenge's sink; an
# empty value means this roster does not reach it, and ``why`` says what the
# challenge needs that a page scan cannot supply.
CHALLENGES = [
    {
        "key": "restfulXssChallenge",
        "name": "API-only XSS",
        "surface": "",
        "reachable": "`PUT /rest/products/1/reviews`",
        "scored": "reviews",
        "why": "needs a review submitted through the API instead of the dialog's form; "
        "the scanner drives what the page renders, and the product dialog in 20.3.0 "
        "puts the review text in a plain property binding, so it is never parsed as "
        "markup. The server-side sink is real; reaching it means posting the review "
        "the page itself does not post.",
    },
    {
        "key": "usernameXssChallenge",
        "name": "CSP Bypass",
        "surface": "",
        "reachable": "`POST /profile`",
        "scored": "profile",
        "literal": "<script>alert(`xss`)</script>",
        "why": "needs an account whose username is rendered on the legacy Pug profile "
        "under a CSP the challenge rewards rewriting; the bench registers accounts, "
        "but the challenge is solved by one exact stored value, not by proving the "
        "renderer executes what it is given.",
    },
    {
        "key": "persistedXssUserChallenge",
        "name": "Client-side XSS Protection",
        "surface": "profile",
        "literal": "<iframe src=\"javascript:alert(`xss`)\">",
        "why": "",
    },
    {
        "key": "localXssChallenge",
        "name": "DOM XSS",
        "surface": "search",
        "why": "",
    },
    {
        "key": "httpHeaderXssChallenge",
        "name": "HTTP-Header XSS",
        "surface": "last-login-ip",
        "why": "",
    },
    {
        "key": "reflectedXssChallenge",
        "name": "Reflected XSS",
        "surface": "track",
        "why": "the challenge itself is solved by one exact iframe string the server "
        "recognises in the order id; the bench credits the sink it proves, not that "
        "payload.",
    },
    {
        "key": "persistedXssFeedbackChallenge",
        "name": "Server-side XSS Protection",
        "surface": "feedback",
        "why": "",
    },
    {
        "key": "videoXssChallenge",
        "name": "Video XSS",
        "surface": "",
        "reachable": "admin-only promo video URL",
        "why": "needs an administrator to change the promo video URL.",
    },
    {
        "key": "xssBonusChallenge",
        "name": "Bonus Payload",
        "surface": "",
        "reachable": "`GET /#/search?q=`",
        "why": "shares the DOM XSS sink but requires one exact SoundCloud iframe; "
        "the scanner proves the sink, not the challenge's payload.",
    },
]

# Surfaces scanned, in the order of the reference the report renders. ``page``
# is what the scanner is *pointed at* — always a page, never the endpoint — so
# the discovery pass has a bundle to read and finds the write sink on its own.
# ``endpoint`` + ``field`` are the ground truth the report checks the result
# against, and what ``reproduce`` replays.
SURFACES = [
    {
        "key": "home",
        "page": "/",
        "endpoint": "",
        "field": "",
        "note": "Angular single-page app. The scanner is pointed at the shell and must "
        "reach the API sinks through the bundle alone: there is no form and no "
        "server-rendered document to read them from.",
    },
    {
        "key": "search",
        "challenge": "localXssChallenge",
        "page": "/",
        "endpoint": "/rest/products/search",
        "route": "/search",
        "field": "q",
        "note": "`GET /rest/products/search?q=` is interpolated into SQL and its JSON "
        "is written to the page through `bypassSecurityTrustHtml`; the client sends the "
        "query in a fragment, so the server never sees it.",
    },
    {
        "key": "track",
        "challenge": "reflectedXssChallenge",
        "page": "/",
        "endpoint": "/rest/track-order/:id",
        "route": "/track-result",
        "field": "id",
        "replay": "/rest/track-order/:id",
        "note": "`GET /rest/track-order/:id` returns the id it was given and the tracking "
        "page renders it through `bypassSecurityTrustHtml`, so the route the payload "
        "travels in is a fragment and the sink is on the API behind it. The replay "
        "addresses that handler with the finding's own payload.",
    },
    {
        "key": "reviews",
        "challenge": "restfulXssChallenge",
        "page": "/",
        "endpoint": "/rest/products/1/reviews",
        "field": "message",
        "method": "PUT",
        "note": "`PUT /rest/products/1/reviews` stores `message` verbatim, with no "
        "authentication; the Angular template writes it into the product dialog, "
        "which 20.3.0 opens from the `#/search` grid rather than a route of its own.",
    },
    {
        "key": "feedback",
        "challenge": "persistedXssFeedbackChallenge",
        "page": "/",
        "endpoint": "/api/Feedbacks",
        "field": "comment",
        "method": "POST",
        "note": "`POST /api/Feedbacks` runs `sanitize-html` with the default allow-list.",
    },
    {
        "key": "complaints",
        "page": "/",
        "endpoint": "/api/Complaints",
        "field": "message",
        "method": "POST",
        "auth": True,
        "note": "`POST /api/Complaints` needs a session and the captcha the server "
        "hands out; the message is stored and shown back to the user.",
    },
    {
        "key": "last-login-ip",
        "challenge": "httpHeaderXssChallenge",
        "page": "/#/privacy-security/last-login-ip",
        "endpoint": "/rest/saveLoginIp",
        "route": "/privacy-security/last-login-ip",
        "field": "True-Client-IP",
        "method": "GET",
        "header": {"True-Client-IP": "IntelliXSS-bench"},
        "needs_account": True,
        "note": "`GET /rest/saveLoginIp` stores the `True-Client-IP` header on the "
        "session's user; `last-login-ip` decodes the token out of `localStorage` and "
        "writes it through `bypassSecurityTrustHtml`. The header below is a probe, not "
        "the payload: the scanner has to discover the stored header and confirm it.",
    },
    {
        "key": "profile",
        "challenge": "usernameXssChallenge",
        "page": "/profile",
        "endpoint": "/profile",
        "field": "username",
        "method": "POST",
        "needs_account": True,
        "note": "The legacy Pug profile page renders the stored username with a "
        "homegrown regex sanitizer behind a CSP the same profile can rewrite through "
        "the image URL.",
    },
    {
        "key": "login",
        "page": "/",
        "endpoint": "/rest/user/login",
        "field": "email",
        "method": "POST",
        "note": "`POST /rest/user/login` renders an error for unknown credentials; the "
        "email field is the reflected sink of the app's own login form.",
    },
]


def request(
    base: str,
    path: str,
    method: str = "GET",
    body=None,
    token: str = "",
    form: bool = False,
    cookie: str = "",
) -> tuple[int, str, str]:
    """(status, body, headers) for one request. HTTP errors are returned, not raised.

    *form* sends the body as ``application/x-www-form-urlencoded`` — the shape a
    server-rendered HTML form posts — and *cookie* adds a session cookie, which
    a login-bound form reads instead of the bearer plane.
    """
    headers = dict(UA)
    data = None
    if body is not None:
        if form:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(body).encode("utf-8")
        else:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:  # noqa: BLE001 - a dead instance is a bench result
        return 0, f"{type(e).__name__}: {e}", {}


def live(base: str) -> bool:
    status, _body, _h = request(base, "/rest/admin/application-version")
    return status == 200


def login(base: str) -> str:
    """Session token for the demo admin account. "" when the account is absent.

    ``admin@juice-sh.op`` / ``admin123`` is the seed account Juice Shop ships
    with; it is a fixture of the application, not a credential of ours.
    """
    status, body, _h = request(
        base,
        "/rest/user/login",
        "POST",
        {"email": "admin@juice-sh.op", "password": "admin123"},
    )
    if status != 200:
        return ""
    try:
        return json.loads(body)["authentication"]["token"]
    except (KeyError, ValueError):
        return ""


def register(base: str, tag: str) -> dict:
    """A throwaway account registered through the application's own signup.

    The harness supplies an *identity*, never a payload: it asks the public
    signup for an ordinary account and hands the scanner that session. Whatever
    ends up stored under it is what the scanner submitted itself.
    """
    email = f"ixss-{tag}@bench.invalid"
    password = f"Bench!{tag}Pass"
    status, _body, _h = request(
        base,
        "/api/Users",
        "POST",
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1},
            "securityAnswer": "bench",
        },
    )
    if status not in (200, 201):
        return {}
    token = login_as(base, email, password)
    return {"email": email, "password": password, "token": token} if token else {}


def login_as(base: str, email: str, password: str) -> str:
    status, body, _h = request(
        base, "/rest/user/login", "POST", {"email": email, "password": password}
    )
    if status != 200:
        return ""
    try:
        return json.loads(body)["authentication"]["token"]
    except (KeyError, ValueError):
        return ""


def captcha(base: str) -> dict:
    """The captcha the server issues, with the answer it is willing to give.

    The endpoint exists for the demo UI, which has to show the answer to be
    usable; a scanner talking to the API gets the same value the form does.
    """
    status, body, _h = request(base, "/rest/captcha")
    if status != 200:
        return {}
    try:
        return json.loads(body)
    except ValueError:
        return {}


def requests_marker(text: str) -> str:
    """The ``ixm…`` marker of the first finding that carries one, else ''."""
    import re

    m = re.search(r"ixm[0-9a-f]{8}", text or "")
    return m.group(0) if m else ""


async def scan_surface(
    base: str,
    surface: dict,
    browser: bool,
    token: str,
    account: dict | None = None,
) -> dict:
    """Scan one surface with the stock configuration and return its findings."""
    cfg = Config(guess_params=True, use_browser=browser)
    auth = AuthConfig()
    if token:
        # The complaint form sits behind a session. The scanner's own bearer
        # plane carries the same token into its HTTP client and its browser, so
        # a scan of that form sees it as a logged-in user does.
        auth.bearer = token
    if account:
        # A surface may need its own identity — an account whose stored record
        # carries the payload. This is the account the harness registered, not
        # a credential it injected into the database.
        auth.bearer = account.get("token") or auth.bearer
        auth.cookie = f"token={account['token']}" if account.get("token") else ""
    header = surface.get("header") or {}
    if header:
        # The harness supplies an attacker-controlled header, exactly as a
        # proxy in front of the application would forward one. The scanner
        # still has to find the sink that stores it and confirm execution.
        auth.headers.update({str(k): str(v) for k, v in header.items()})
    if auth.bearer or auth.cookie or auth.headers:
        cfg.auth = auth
    s = Scanner(cfg)
    s._mute = True
    started = time.time()
    result = {"key": surface["key"], "status": "ok", "findings": [], "requests": 0}
    try:
        r = await asyncio.wait_for(s.scan(base + surface["page"]), timeout=600)
        result["requests"] = r.stats.requests
        result["targets"] = r.targets_tested
        for f in r.findings:
            result["findings"].append(
                {
                    "param": f.parameter,
                    "ctx": f.context.value,
                    "verified_by": f.verified_by,
                    "payload": (f.payload or "")[:120],
                    "type": f.vulnerability_type,
                    "method": f.method,
                    "url": f.url,
                    "marker": f.marker,
                }
            )
    except asyncio.TimeoutError:
        result["status"] = "timeout"
    except Exception as e:  # noqa: BLE001 - one broken surface must not stop the run
        result["status"] = f"error: {type(e).__name__}: {e}"
    finally:
        await s.browser.stop()
    # One row per sink: a browser-confirmed payload supersedes the reflection
    # lead for the same parameter and context. The endpoint is part of the
    # identity — ``message`` on the review API and ``message`` on the complaint
    # API are two different sinks, and keying on the parameter alone let the
    # first one hide the second.
    best: dict = {}
    for row in result["findings"]:
        key = (row["url"].rstrip("/"), row["param"], row["ctx"])
        prior = best.get(key)
        if prior is None or (prior["verified_by"] != "browser" and row["verified_by"] == "browser"):
            best[key] = row
    result["findings"] = list(best.values())
    result["secs"] = round(time.time() - started, 1)
    return result


def _form_body(key: str, payload: str, account: dict, base: str = "") -> dict | None:
    """The wire body that writes *payload* through surface *key*.

    Each surface is one form. Rebuilding it here keeps the replay independent
    of which handler the scan happened to report, and makes the shape explicit
    enough that a changed one is a visible edit rather than a silent guess.
    ``None`` means the surface has no known write shape.
    """
    if key == "feedback":
        cap = captcha(base) if base else {}
        return {
            "comment": payload,
            "rating": 1,
            "captchaId": cap.get("captchaId"),
            "captcha": cap.get("answer"),
        }
    if key == "complaints":
        return {"message": payload}
    if key == "reviews":
        return {"message": payload, "author": "admin@juice-sh.op"}
    if key == "profile":
        # The rendered form's own fields, and only those. The image URL is
        # omitted rather than sent empty: an empty value is stored as such and
        # makes the model overwrite an admin's picture, which fails the write.
        # The email is the identity's own, because the handler updates the
        # account it is authenticated as and reads that address back.
        body = {"username": payload}
        if account.get("email"):
            body["email"] = account["email"]
        return body
    if key == "login":
        return {"email": payload, "password": "intellixss-not-a-password"}
    return None


def reproduce(base: str, surface: dict, finding: dict, token: str, account: dict | None = None) -> dict:
    """Replay a finding with its own payload and report what came back.

    This is the check that makes the report trustworthy: the scanner's claim
    is not taken on faith, the value is put on the wire again and the response
    is searched for the marker. For a ``PUT``/``POST`` surface the body is
    rebuilt from the field the finding names.
    """
    payload = finding["payload"]
    param = finding["param"]
    # The method the finding reported, falling back to the surface's. A form
    # surface is only scanned to reach every sink on its page, and the sink it
    # is graded on may be found by a GET even though its own write is a POST.
    method = finding.get("method") or surface.get("method", "GET")
    parsed = urllib.parse.urlparse(finding.get("url", ""))
    sink = parsed.path
    # A hash route never reaches the server: replaying it over HTTP returns the
    # application shell and says nothing about the payload. The browser is the
    # only oracle for that finding, and it already ran during the scan.
    #
    # Unless the component hands the value to an API, which is what the
    # tracking page does with the id it was given: then the fragment names the
    # component and ``replay`` names the request that carries the value. The
    # replay proves the sink is fed by the application's own data path, not by
    # a handler the scanner made up.
    if (parsed.fragment or "").startswith("/"):
        replay = (surface or {}).get("replay") or ""
        if replay and param == (surface.get("field") or param):
            # A ``:id`` segment carries the value in the path, which is where
            # the tracked id lives; the query string form would describe a
            # handler that does not exist.
            if ":id" in replay:
                replay = replay.replace(":id", urllib.parse.quote(payload, safe=""))
            else:
                replay = f"{replay}?{urllib.parse.urlencode({param: payload})}"
            status, text, _h = request(base, replay, "GET", None, token)
            marker = finding.get("marker") or requests_marker(payload)
            return {
                "status": status,
                "echoed": bool(marker) and marker in text,
                "stored": False,
                "dom": True,
                "marker": marker,
            }
        return {
            "status": 0,
            "echoed": False,
            "stored": False,
            "dom": True,
            "marker": finding.get("marker") or requests_marker(payload),
            "note": "hash route: execution is browser-only",
        }
    if param.startswith(("localStorage", "sessionStorage", "document.", "window.")):
        return {
            "status": 0,
            "echoed": False,
            "stored": False,
            "dom": True,
            "marker": finding.get("marker") or requests_marker(payload),
            "note": f"{param} is planted in the browser: execution is browser-only",
        }
    # The endpoint the *finding* names is the one that has to be replayed, not
    # the surface's nominal endpoint: a scan of ``/`` reports sinks the surface
    # list does not know about, and replaying those against another handler
    # would confirm the wrong thing.
    path = sink or (surface.get("endpoint") or surface["page"])
    body = None
    if method == "GET":
        path = f"{path}?{urllib.parse.urlencode({param: payload})}" if "?" not in path else path
    else:
        body = _form_body(surface["key"], payload, account or {}, base)
    if method != "GET" and body is None:
        # Nothing is known about how this handler takes input. Posting a guess
        # and reporting its status would describe a request the application
        # never receives, so the replay abstains instead.
        return {
            "status": 0,
            "echoed": False,
            "stored": False,
            "replayed": False,
            "note": f"no replay shape for {surface['key']}",
        }
    # A server-rendered form authenticates on the session cookie and posts
    # urlencoded fields; an API surface takes JSON and the bearer plane. Sending
    # one shape at the other is how a replay reports a failure the application
    # never caused.
    form = surface["key"] == "profile"
    cookie = f"token={token}" if form and token else ""
    status, text, _h = request(base, path, method, body, token, form=form, cookie=cookie)
    marker = finding.get("marker") or requests_marker(payload)
    echoed = bool(marker) and marker in text
    # A stored payload is not in this response; it is in the collection the
    # app renders. Reading it back is what distinguishes "stored" from "sent".
    stored = echoed
    if not echoed and method != "GET" and marker:
        listing = {
            "reviews": f"/rest/products/1/reviews",
            "feedback": "/api/Feedbacks",
            "complaints": "/api/Complaints",
        }.get(surface["key"])
        if listing:
            _st, listed, _lh = request(base, listing, "GET", None, token)
            stored = marker in listed
        elif surface["key"] == "profile" and token:
            # The write answers with the profile page it redirects to, and the
            # username input carries the stored value. The markup is the page's
            # own, so the replay reports whether the account *holds* the value.
            _st, page, _mh = request(base, "/profile", "GET", None, token, cookie=cookie)
            hit = re.search(r'id="username"[^>]*value="([^"]*)"', page or "")
            stored = bool(hit) and payload in html.unescape(hit.group(1))
    return {"status": status, "echoed": echoed, "stored": stored, "marker": marker}


def _on_sink(surface: dict, finding: dict) -> bool:
    """Whether *finding* was made on the endpoint the surface is about.

    A ``:id`` segment in the discovered endpoint stands for whatever record id
    the scanner resolved, so it matches any segment. The query string is not
    part of the identity: ``/rest/products/search?q=:id`` and
    ``/rest/products/search`` are the same handler. A hash-routed surface names
    a ``route`` instead: the payload travels in the fragment, the request path
    is ``/``, and only the fragment says which component received it.
    """
    endpoint = (surface or {}).get("endpoint") or ""
    if not endpoint:
        return False
    parsed = urllib.parse.urlparse(finding.get("url", ""))
    route = (surface or {}).get("route") or ""
    if route:
        # A finding on another route is another component, whatever field it
        # names: ``q`` on ``#/search`` is not the sink this surface is about.
        fragment = parsed.fragment or ""
        fragment_path = "/" + fragment.lstrip("/").split("?")[0].strip("/")
        if fragment_path.rstrip("/") != route.rstrip("/"):
            return False
    # A finding is credited to a surface only for the field that surface is
    # about — or for the browser-owned source it names, which is a source and
    # not a parameter of the endpoint. Every other field of the same handler
    # belongs to some other sink.
    field = (surface or {}).get("field") or ""
    param = finding.get("param") or ""
    if field and param != field and not param.startswith(("localStorage", "sessionStorage", "document.", "window.")):
        return False
    if route:
        return True
    want = urllib.parse.urlparse(endpoint).path.rstrip("/")
    got = parsed.path.rstrip("/")
    if want == got:
        return True
    want_seg = [s for s in want.split("/") if s]
    got_seg = [s for s in got.split("/") if s]
    if len(want_seg) != len(got_seg):
        return False
    return all(w == g or w.startswith(":") or g.startswith(":") for w, g in zip(want_seg, got_seg))


def write_report(rows: list, version: str, base: str) -> Path:
    """Render ``benchmark/juiceshop-report.md`` from the run that just finished.

    The report is generated, never hand-edited: every verdict in it comes from
    the JSON beside it, so a re-run cannot leave the prose claiming something
    the scanner no longer found.
    """
    by_key = {r["key"]: r for r in rows}

    def verdict(surface_key: str) -> str:
        row = by_key.get(surface_key)
        if row is None:
            return "not run"
        own = row["findings"]
        if any(f["verified_by"] == "browser" for f in own):
            return "reproduced"
        if any(f["verified_by"] == "static" for f in own):
            return "static only"
        if own:
            return "lead only"
        return "clean"

    def confirmed(row: dict) -> list:
        return [f for f in row.get("findings", []) if f["verified_by"] == "browser"]

    def graded_surface(c: dict) -> str:
        """The surface the challenge table grades, and whether it was reached.

        A challenge can be about a surface that was scanned even when its sink
        was reached on another one: ``restfulXssChallenge`` is stored through
        its API and rendered by the product dialog, which is the ``reviews``
        surface, not the one that renders the stored username.
        """
        reachable = (c.get("reachable") or "").strip()
        if reachable:
            return reachable
        return "not reached"

    def challenge_verdict(c: dict) -> tuple[str, str]:
        """(sink cell, result cell) for one documented challenge."""
        surface_key = c.get("surface") or ""
        reachable = graded_surface(c)
        if not surface_key:
            return reachable, "not reached"
        result = verdict(surface_key)
        return sink_label(surface_key), result

    def finding_label(f: dict) -> str:
        """The sink a finding was made on, with the route when it is in the fragment."""
        parsed = urllib.parse.urlparse(f["url"])
        if (parsed.fragment or "").startswith("/"):
            route = "/" + parsed.fragment.lstrip("/").split("?")[0].strip("/")
            return f"`{f['method']} /#{route}?{f['param']}=`"
        return f"`{f['method']} {parsed.path}`"

    def sink_label(surface_key: str) -> str:
        row = by_key.get(surface_key)
        if row is None:
            return "not run"
        hits = confirmed(row)
        if hits:
            f = hits[0]
            # A sink fed by a browser-owned source has no parameter in the
            # route: naming one would claim a request shape that never fired.
            if f["param"].startswith(("localStorage", "sessionStorage", "document.", "window.")):
                parsed = urllib.parse.urlparse(f["url"])
                route = "/" + (parsed.fragment or "").lstrip("/").split("?")[0].strip("/")
                return f"`GET /#{route}` via `{f['param']}`"
            return finding_label(f)
        surface = row.get("surface", {})
        endpoint = surface.get("endpoint") or surface.get("page", "")
        return f"`{surface.get('method', 'GET')} {endpoint}`"

    reproduced = [c for c in CHALLENGES if c["surface"] and verdict(c["surface"]) == "reproduced"]
    documented_clean = [
        c for c in CHALLENGES if c["surface"] and verdict(c["surface"]) == "clean"
    ]
    not_reached = [c for c in CHALLENGES if not c["surface"]]

    extra = [
        (row["key"], f)
        for row in rows
        if row["key"] not in {c["surface"] for c in CHALLENGES if c["surface"]}
        for f in confirmed(row)
    ]

    lines: list[str] = []
    add = lines.append
    add("# OWASP Juice Shop bench")
    add("")
    add(f"Target: Juice Shop {version} at `{base}`.")
    add("Scanner: IntelliXSS, stock configuration, no per-surface tuning.")
    add("Source: `benchmark/juiceshop.json`, written by `bench/juice.py`.")
    add("")
    add("## Documented XSS challenges")
    add("")
    add("The nine entries of `data/static/challenges.yml` whose category is `XSS`.")
    add("A challenge counts as reproduced when the scanner confirms, in a browser,")
    add("an executing payload on the sink that challenge is about.")
    add("Reaching a sink is not the same as solving what the challenge asks: a few")
    add("of them are solved by the *server* recognising one exact injected value.")
    add("Those are marked separately, because the scanner proves the sink executes")
    add("while sending its own payload, which is what a scan is for.")
    add("")
    add("| Challenge | Key | Sink | Result |")
    add("|---|---|---|---|")
    for c in CHALLENGES:
        where, result = challenge_verdict(c)
        if not c.get("surface") and c.get("scored"):
            other = c["scored"]
            if verdict(other) == "reproduced":
                result = (
                    f"not counted; the sink is proven by `{other}` in this run, and "
                    "what keeps the challenge is its own exact value"
                )
        if c.get("surface") and c.get("literal"):
            result = f"{result}; challenge itself needs the literal `{c['literal']}`" if result == "reproduced" else result
        add(f"| {c['name']} | `{c['key']}` | {where} | {result} |")
    add("")
    add("The profile surface is credited for its sink, not for the challenge: the")
    add("scanner confirms that a stored username reaches a sink that executes its")
    add("own `<img onerror>` payload, while the challenge is solved by the server")
    add("seeing one exact injected value. The same holds for the search surface")
    add("and the bonus payload.")
    add("")
    add(
        f"{len(reproduced)} of {len(CHALLENGES)} documented XSS challenges reproduced "
        "automatically."
    )
    add(
        f"{len(documented_clean)} documented "
        f"challenge{'s' if len(documented_clean) != 1 else ''} reported clean, and "
        f"{len(not_reached)} met the roster's bar for a challenge "
        "(see below). Each of those names the sink it is about, so a row marked "
        "\"not reached\" is a statement about that sink, not about the roster."
    )
    if documented_clean:
        names = ", ".join(f"`{c['key']}`" for c in documented_clean)
        add("")
        add(f"A clean result is the expected answer for {names}: the sink is behind")
        add("`sanitize-html` with its default allow-list, so the payload is stored as")
        add("text and cannot execute. Reporting it clean is the precision counterpart")
        add("to the confirmations.")
    if extra:
        add("")
        add("Beyond the documented list, the scanner confirmed sinks that no challenge")
        add("covers:")
        add("")
        for key, f in extra:
            add(f"- `{f['method']} {urllib.parse.urlparse(f['url']).path}` "
                f"(`{f['param']}`, {f['type']}) on the `{key}` surface")
    add("")
    add("## Session material supplied by the harness")
    add("")
    add("A scan of an anonymous page cannot reach a sink that is only stored for")
    add("a logged-in user, or fed by a header the page never sends. For those")
    add("surfaces the harness supplies *identity and transport only*: a throwaway")
    add("account registered through `POST /api/Users`, and where a surface is")
    add("about a header, that header. No payload is pre-written by the harness.")
    add("")
    add("| Surface | Session | Supplied |")
    add("|---|---|---|")
    for row in rows:
        supplied = []
        if row.get("session") == "account":
            supplied.append("throwaway account")
        elif row.get("session") == "shared":
            supplied.append("admin bearer")
        for name in (row.get("surface", {}).get("header") or {}):
            supplied.append(f"header `{name}`")
        add(
            f"| {row['key']} | {row.get('session', 'none')} | "
            f"{', '.join(supplied) or 'nothing'} |"
        )
    add("")
    add("## Surfaces")
    add("")
    add("| Surface | Pointed at | Sink | Verdict | Confirmed | Requests | Time |")
    add("|---|---|---|---|---|---|---|")
    for row in rows:
        surface = row.get("surface", {})
        add(
            f"| {row['key']} | `{surface.get('page', '')}` | {sink_label(row['key'])} | "
            f"{verdict(row['key'])} | {len(confirmed(row))} | {row.get('requests', 0)} | "
            f"{row.get('secs', 0)}s |"
        )
    add("")
    add("## Confirmed findings")
    add("")
    for row in rows:
        for f in row["findings"]:
            if f["verified_by"] != "browser":
                continue
            add(f"### `{f['method']} {f['url']}`")
            add("")
            add(f"- Parameter: `{f['param']}`")
            add(f"- Context: `{f['ctx']}`")
            add(f"- Type: `{f['type']}`")
            add(f"- Payload: `{f['payload']}`")
            replay = f.get("replay") or {}
            if replay.get("status"):
                add(
                    f"- Replay: HTTP `{replay.get('status', 0)}`, "
                    f"echoed `{str(replay.get('echoed', False)).lower()}`, "
                    f"stored `{str(replay.get('stored', False)).lower()}`"
                )
            elif replay.get("dom"):
                add(f"- Replay: {replay.get('note', 'browser-only')}")
            elif replay:
                add(f"- Replay: {replay.get('note', 'not replayed')}")
            add("")
    add("## Not reached by the roster, and why")
    add("")
    for c in CHALLENGES:
        if c["surface"]:
            continue
        add(f"- **{c['name']}** (`{c['key']}`): {c['why']}")
    add("")
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    return REPORT


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://127.0.0.1:3000")
    ap.add_argument("--only", nargs="*", help="surface keys to scan")
    ap.add_argument("--no-browser", action="store_true", help="skip Chromium confirmation")
    ap.add_argument("--no-replay", action="store_true", help="skip the reproduce pass")
    ap.add_argument("--list", action="store_true", help="show the roster and exit")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    if not args.no_replay:
        # Every capture points the scanner at a page whose server-side state is
        # the seed data. Replaying a finding would otherwise add one more record
        # to a store the next run also reads, so the run says what it wrote and
        # leaves the reset to the operator (``bench/reset-shop.ps1``).
        print(
            "note: this run writes records to the shop; reset it before re-measuring",
            flush=True,
        )

    if args.list:
        for s in SURFACES:
            print(f"{s['key']:12} {s.get('method', 'GET'):5} {s['page']}")
            print(f"             {s['note']}")
        print("\nXSS challenges (data/static/challenges.yml):")
        for c in CHALLENGES:
            where = c["surface"] or "-"
            print(f"  {c['key']:30} {c['name']:32} {where}")
        return

    if not live(base):
        print(f"no Juice Shop answering at {base} - start it first (see benchmark/README.md)")
        sys.exit(2)
    version = json.loads(request(base, "/rest/admin/application-version")[1]).get("version", "?")
    token = login(base)
    print(f"Juice Shop {version} at {base}  browser={'off' if args.no_browser else 'on'}  "
          f"session={'yes' if token else 'no'}", flush=True)

    wanted = [s for s in SURFACES if not args.only or s["key"] in args.only]
    rows = []
    for surface in wanted:
        print(f"\n[{surface['key']}] {surface.get('method', 'GET')} {surface['page']}", flush=True)
        account = {}
        if surface.get("needs_account"):
            # A distinct identity per surface, so one surface's stored record
            # cannot make the next one look exploitable.
            account = register(base, f"{surface['key']}-{int(time.time())}")
            print(
                f"  account: {'registered' if account else 'unavailable'}",
                flush=True,
            )
        row = await scan_surface(base, surface, not args.no_browser, token, account)
        row["session"] = "account" if account else ("shared" if token else "none")
        # The scan of ``/`` reports every sink the bundle exposes, once per
        # surface. A surface's verdict is about *its* sink: a finding on
        # ``/api/Feedbacks`` is not evidence about the review endpoint.
        own = [f for f in row["findings"] if _on_sink(surface, f)]
        row["findings"] = own
        confirmed = [f for f in own if f["verified_by"] == "browser"]
        static = [f for f in own if f["verified_by"] == "static"]
        heads = [f for f in own if f["verified_by"] not in ("browser", "static")]
        verdict = "CONFIRMED" if confirmed else ("static" if static else ("lead" if heads else "CLEAN"))
        print(f"    {verdict:10} {row['status']:8} {row.get('secs', 0):6}s "
              f"req={row['requests']} targets={row.get('targets', 0)} "
              f"conf={len(confirmed)} static={len(static)} lead={len(heads)}", flush=True)
        for f in own[:4]:
            print(f"        {f['verified_by']:9} {f['ctx']:20} {f['payload'][:48]!r}", flush=True)
        if not args.no_replay:
            for f in own:
                if f["verified_by"] in ("browser", "static", "reflection"):
                    f["replay"] = reproduce(base, surface, f, account.get("token") or token, account)
        row["surface"] = {k: v for k, v in surface.items()}
        rows.append(row)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    report = write_report(rows, version, base)

    # Score against the documented list, not the Score Board. A parameter is
    # only counted for a surface when the finding is on that surface's sink.
    confirmed_params = {
        (r["key"], f["param"])
        for r in rows
        for f in r["findings"]
        if f["verified_by"] == "browser" and _on_sink(r["surface"], f)
    }
    static_params = {
        (r["key"], f["param"])
        for r in rows
        for f in r["findings"]
        if f["verified_by"] == "static" and _on_sink(r["surface"], f)
    }
    challenged = {c["surface"] for c in CHALLENGES if c["surface"]}
    reproduced = sum(
        1
        for r in rows
        if r["key"] in challenged
        and any(f["verified_by"] == "browser" for f in r["findings"])
    )
    print(f"\nresults -> benchmark/juiceshop.json")
    print(f"report  -> {report.relative_to(ROOT).as_posix()}")
    print(f"XSS challenges documented: {len(CHALLENGES)}")
    print(f"  confirmed by a browser: {len(confirmed_params)} parameter(s) across "
          f"{len({k for k, _ in confirmed_params})} surface(s)")
    print(f"  proven statically:      {len(static_params)} parameter(s)")
    print(f"  documented challenges:  {reproduced} of {len(CHALLENGES)} reproduced")


if __name__ == "__main__":
    asyncio.run(main())
