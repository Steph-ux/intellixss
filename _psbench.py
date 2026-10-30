"""XSS-lab bench: launch each PortSwigger lab, scan it, report precision/recall.

Usage:
    python _psbench.py            # all labs
    python _psbench.py 0 6        # labs 0..5 inclusive
    python _psbench.py --list     # show the roster

The session cookie is read from ``D:\\tmp\\cookie.py`` (browser cookie export).
Each lab is launched through ``/academy/labs/launch/<LABID>``; the redirect
target is the live instance host.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
import urllib.request
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

from intellixss.auth import AuthConfig
from intellixss.config import Config
from intellixss.scanner.orchestrator import Scanner

BASE = "https://portswigger.net"
COOKIE_FILE = Path(r"D:\tmp\cookie.py")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

LABS = [
    # (path, difficulty, family)
    ("cross-site-scripting/reflected/lab-html-context-nothing-encoded", "APPRENTICE", "reflected-html"),
    ("cross-site-scripting/stored/lab-html-context-nothing-encoded", "APPRENTICE", "stored-html"),
    ("cross-site-scripting/dom-based/lab-document-write-sink", "APPRENTICE", "dom-document.write"),
    ("cross-site-scripting/dom-based/lab-innerhtml-sink", "APPRENTICE", "dom-innerhtml"),
    ("cross-site-scripting/dom-based/lab-jquery-href-attribute-sink", "APPRENTICE", "dom-jquery-href"),
    ("cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event", "APPRENTICE", "dom-jquery-selector"),
    ("cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded", "APPRENTICE", "attr-double"),
    ("cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded", "APPRENTICE", "href-attr"),
    ("cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded", "APPRENTICE", "js-string"),
    ("cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element", "PRACTITIONER", "dom-select"),
    ("cross-site-scripting/dom-based/lab-angularjs-expression", "PRACTITIONER", "angularjs"),
    ("cross-site-scripting/dom-based/lab-dom-xss-reflected", "PRACTITIONER", "dom-reflected"),
    ("cross-site-scripting/dom-based/lab-dom-xss-stored", "PRACTITIONER", "dom-stored"),
    ("cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked", "PRACTITIONER", "waf-tags"),
    ("cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked", "PRACTITIONER", "waf-custom-tag"),
    ("cross-site-scripting/contexts/lab-some-svg-markup-allowed", "PRACTITIONER", "svg-allowlist"),
    ("cross-site-scripting/contexts/lab-canonical-link-tag", "PRACTITIONER", "canonical-link"),
    ("cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped", "PRACTITIONER", "js-sq-escaped"),
    ("cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-encoded-single-quotes-escaped", "PRACTITIONER", "js-sq-escaped2"),
    ("cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped", "PRACTITIONER", "onclick-escaped"),
    ("cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped", "PRACTITIONER", "template-literal"),
    ("cross-site-scripting/exploiting/lab-stealing-cookies", "PRACTITIONER", "stored-cookie"),
    ("cross-site-scripting/exploiting/lab-capturing-passwords", "PRACTITIONER", "stored-password"),
    ("cross-site-scripting/exploiting/lab-perform-csrf", "PRACTITIONER", "stored-csrf"),
    ("cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings", "EXPERT", "angular-sandbox"),
    ("cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp", "EXPERT", "angular-csp"),
    ("cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked", "EXPERT", "waf-events-href"),
    ("cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked", "EXPERT", "js-url-blocked"),
    ("cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack", "EXPERT", "csp-dangling"),
    ("cross-site-scripting/content-security-policy/lab-csp-bypass", "EXPERT", "csp-bypass"),
]


def build_opener():
    # The browser export carries secure, HttpOnly, session-scoped and
    # SameSite-tagged cookies. ``CookieJar`` silently drops several of those
    # combinations (a session cookie with ``discard`` and no expiry, in
    # particular), and the resulting request lands on the login page even
    # though the export is valid. Sending the jar as one explicit ``Cookie``
    # header keeps every value the browser held — which is what the site sees
    # from the browser itself.
    raw = json.load(open(COOKIE_FILE, encoding="utf-8-sig"))
    parts = [
        f"{c['name']}={c['value']}"
        for c in raw
        if c.get("domain", "").lstrip(".") == "portswigger.net"
        and "posthog" not in c["name"]
        and "stripe" not in c["name"]
    ]
    return urllib.request.build_opener(urllib.request.BaseHandler()), "; ".join(parts)


OPENER, COOKIE_HEADER = build_opener()


def get(url: str) -> tuple[int, str, str]:
    headers = dict(UA)
    if "portswigger.net" in url:
        headers["Cookie"] = COOKIE_HEADER
    last = ""
    for attempt in range(3):
        try:
            r = OPENER.open(urllib.request.Request(url, headers=headers), timeout=45)
            return r.status, r.geturl(), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, url, e.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - connection resets are expected
            last = f"{type(e).__name__}: {e}"
            time.sleep(1.5 * (attempt + 1))
    return 0, url, f"ERROR {last}"


def launch(path: str, attempts: int = 3) -> str | None:
    """Return the live instance base URL for a lab page path.

    PortSwigger's launch redirect intermittently answers 200 with the plain lab
    description instead of building an instance. That is upstream flakiness, not
    a permission problem, and a second request a few seconds later succeeds — so
    the launch is retried before being reported as unavailable.
    """
    st, _f, body = get(f"{BASE}/web-security/{path}")
    m = re.search(r'widget-lab-id="([0-9A-F]{64})"', body)
    if not m:
        # The lab page no longer embeds the id in a widget of its own: the
        # launch widget is filled in by the client. The id is still in the
        # markup as the lab's identifier, so a plain scan for it recovers the
        # launch key without depending on which widget carries it.
        m = re.search(r"\b([0-9A-F]{64})\b", body)
    if not m:
        print(f"    ! no lab id (st={st})")
        return None
    lab_id = m.group(1)

    for attempt in range(attempts):
        for candidate in (lab_id, lab_id.lower()):
            st, final, page = get(
                f"{BASE}/academy/labs/launch/{candidate}?referrer=/web-security/{path}"
            )
            # A successful launch lands the request *on the instance*, so the
            # final URL is the instance itself (``…c2.web-security-academy.net``
            # or ``…53.h1-web-security-academy.net``) with no path. The
            # subdomain may be 32 characters or shorter, so the width is not
            # pinned.
            inst = re.search(
                r"(https://[a-z0-9]{8,40}(?:\.[a-z0-9]{1,4})?[-.]web-security-academy\.net)/?",
                final + page,
            )
            if inst:
                return inst.group(1)
        if attempt + 1 < attempts:
            time.sleep(4)
    print(f"    ! no instance after {attempts} attempts (st={st} len={len(page)})")
    return None


def discover_pages(inst: str, limit: int = 2) -> list[str]:
    """Pages worth scanning besides the landing page, same origin only.

    Two sources: the article/detail links the landing page offers (the sink of
    most labs sits on one of those), and the account page when the site links
    it — a lab whose sink is behind a login offers no other route to it.
    """
    _st, _f, body = get(inst + "/")
    out: list[str] = []
    for m in re.finditer(r'href="(/[^"#?]*\?(?:postId|id|productId|itemId)=\d+)"', body):
        page = inst + m.group(1)
        if page not in out:
            out.append(page)
        if len(out) >= limit:
            break
    # A lab whose entry point is the last article it seeded does not always
    # link it from the list: the post that carries the comments form is the one
    # the list is taken from. Try that id as well, so the form is scanned even
    # when its link is not rendered.
    ids = [int(x) for x in re.findall(r"(?:postId|productId|itemId)=(\d+)", body)]
    if ids:
        guess = inst + f"/post?postId={max(ids)}"
        if guess not in out and not any("postId=" in p for p in out):
            out.append(guess)
    # The account page is a sink in its own right: it renders the pending email
    # value straight into an attribute, and its change-email form posts the
    # same name. It is only reachable for a session, so it is scanned last and
    # an anonymous scan simply sees the login redirect.
    if re.search(r'href="[^"]*/my-account"', body) and inst + "/my-account" not in out:
        out.append(inst + "/my-account")
    return out


async def scan_one(url: str, extra: list[str] | None = None) -> dict:
    """Scan *url*, and every page in *extra*, as one result.

    Many labs hold no form on the landing page: the injected field lives in a
    comment form on an article page, and the value is rendered back on that same
    article. Scanning only "/" tests a page with no sink at all, so the bench
    follows the links the lab itself offers, exactly as a tester would.

    Labs whose surface is behind a login are scanned with the account the page
    itself advertises, so the session reaches the HTTP client and the browser.
    """
    cfg = Config(guess_params=True)
    cfg.auth = AuthConfig(username="wiener", password="peter")
    s = Scanner(cfg)
    s._mute = True
    t0 = time.time()
    merged: dict = {"findings": [], "requests": 0, "status": "ok"}
    try:
        # A page named twice is scanned twice: the second pass overwrites the
        # first, so a browser confirmation reached on the first pass would be
        # replaced by the reflection lead the second one progresses through
        # before it confirms.
        pages: list = []
        for page in [url] + list(extra or []):
            if page not in pages:
                pages.append(page)
        for page in pages:
            try:
                r = await asyncio.wait_for(s.scan(page), timeout=300)
            except asyncio.TimeoutError:
                merged["status"] = "timeout"
                continue
            merged["requests"] += r.stats.requests
            for f in r.findings:
                # Key by *evidence quality* too: the same sink reports both a
                # reflection-only lead and the browser-confirmed payload, and
                # collapsing them by (param, ctx) alone keeps whichever came
                # second — which hid the confirmed one behind the lead.
                key = (f.parameter, f.context.value, f.verified_by)
                row = {
                    "param": f.parameter,
                    "ctx": f.context.value,
                    "verified_by": f.verified_by,
                    "sev": f.severity.value,
                    "payload": (f.payload or "")[:70],
                    "page": page,
                }
                # The same sink reached from two pages must keep its *best*
                # evidence: an earlier unconfirmed copy would otherwise hide a
                # later browser-confirmed one.
                prev = next(
                    (g for g in merged["findings"] if g["key"] == key),
                    None,
                )
                row["key"] = key
                if prev is None:
                    merged["findings"].append(row)
                elif row["verified_by"] == "browser" and prev["verified_by"] != "browser":
                    # The better evidence replaces the lead in place. Keeping
                    # both would report one sink twice.
                    for k, v in row.items():
                        prev[k] = v
    finally:
        await s.browser.stop()
    merged["secs"] = round(time.time() - t0, 1)
    for row in merged["findings"]:
        row.pop("key", None)
    # Within one sink, one row is the report: a browser-confirmed payload
    # supersedes the reflection lead for the same parameter and context, and
    # reporting both counts one vulnerability twice.
    best: dict = {}
    for row in merged["findings"]:
        key = (row["param"], row["ctx"])
        prior = best.get(key)
        if prior is None or (
            prior["verified_by"] != "browser" and row["verified_by"] == "browser"
        ):
            best[key] = row
    merged["findings"] = list(best.values())
    return merged


def _load_report() -> list:
    p = Path("_psreport.json")
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


async def main() -> None:
    args = sys.argv[1:]
    if "--list" in args:
        for i, (p, d, fam) in enumerate(LABS):
            print(f"{i:2} {d:12} {fam:18} {p}")
        return

    numbered = [a for a in args if a.isdigit()]
    only = [a for a in args if not a.isdigit() and not a.startswith("-")]
    if numbered:
        # ``_psbench.py 16 17`` scans the inclusive index range 16..17.
        start = int(numbered[0])
        end = int(numbered[1]) if len(numbered) > 1 else start
    else:
        start, end = 0, len(LABS) - 1
    results = []
    for i in range(start, min(end, len(LABS) - 1) + 1):
        path, diff, fam = LABS[i]
        if only and fam not in only and path not in only:
            continue
        print(f"\n[{i:2}] {diff:12} {fam:18} {path}", flush=True)
        inst = launch(path)
        if not inst:
            print("    SKIP (no instance)", flush=True)
            results.append({"i": i, "path": path, "diff": diff, "fam": fam, "status": "no-instance"})
            continue
        print(f"    instance {inst}", flush=True)
        pages = discover_pages(inst)
        res = await scan_one(inst + "/", pages)
        conf = [f for f in res["findings"] if f["verified_by"] == "browser"]
        static = [f for f in res["findings"] if f["verified_by"] != "browser"]
        verdict = "CONFIRMED" if conf else ("static" if static else "CLEAN")
        print(f"    {verdict:10} {res['status']:8} {res['secs']:6}s req={res.get('requests',0)} "
              f"conf={len(conf)} static={len(static)} pages={1 + len(pages)}", flush=True)
        for f in res["findings"][:4]:
            print(f"        {f['verified_by']:7} {f['ctx']:20} {f['payload'][:52]!r}", flush=True)
        results.append({"i": i, "path": path, "diff": diff, "fam": fam, "instance": inst, **res})

    # The report accumulates: a bench that only ran slice ``22..25`` must not
    # erase the eighteen labs measured before it. Rows are keyed by lab index
    # and the newest measurement of a lab wins.
    merged = {r["i"]: r for r in _load_report()}
    for r in results:
        merged[r["i"]] = r
    rows = [merged[i] for i in sorted(merged)]
    Path("_psreport.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    ok = [r for r in rows if r.get("status") == "ok"]
    conf = [r for r in ok if any(f["verified_by"] == "browser" for f in r["findings"])]
    stat = [r for r in ok if r["findings"] and not any(f["verified_by"] == "browser" for f in r["findings"])]
    print(
        f"\nscan+={len(results)}  report={len(rows)} labs  "
        f"confirmed={len(conf)} static-only={len(stat)} clean={len(ok)-len(conf)-len(stat)}"
    )
    missing = [i for i in range(len(LABS)) if i not in merged]
    print(f"missing labs={missing or '-'}  -> _psreport.json")


if __name__ == "__main__":
    asyncio.run(main())
