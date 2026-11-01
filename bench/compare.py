"""Three-way XSS scanner benchmark on a common local range.

Points IntelliXSS, Dalfox and (optionally) XSStrike at the identical
``bench/range.py`` server and scores each the same way:

* **recall**    — of the 7 vulnerable endpoints, how many the scanner flags.
* **precision** — of the endpoints it flags, how many are actually vulnerable
                  (the 3 clean controls are there to catch over-reporting).
* **confirmed** — how many it proves by execution (IntelliXSS browser marker /
                  Dalfox ``V`` verified), not just reflection.
* **time**      — wall-clock for the whole range.

Everything here runs the scanners as black boxes through their own CLIs, so the
numbers are reproducible and not tuned to any one tool. XSStrike is opt-in
(``--with-xsstrike``) because it is third-party code the harness only runs when
the operator asks it to.

Usage::

    python bench/compare.py --dalfox-bin ./dalfox [--with-xsstrike DIR] \
        --out benchmark/comparison.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Imported from the range so the two files cannot drift.
sys.path.insert(0, str(HERE))
from range import ENDPOINTS  # noqa: E402

VULN = [n for n, (v, *_rest) in ENDPOINTS.items() if v]
CLEAN = [n for n, (v, *_rest) in ENDPOINTS.items() if not v]


def _url(base: str, name: str) -> str:
    return f"{base}/{name}?q=1"


# --- scanners: each returns (flagged: bool, confirmed: bool) for one URL ---


def run_intellixss(base: str, name: str, timeout: int) -> tuple[bool, bool]:
    url = _url(base, name)
    try:
        out = subprocess.run(
            [sys.executable, str(ROOT / "intellixss.py"), "-u", url, "--json", "-r", "50"],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        ).stdout
        doc = json.loads(out)
        doc = doc[0] if isinstance(doc, list) else doc
        findings = doc.get("findings", [])
        flagged = any(f.get("parameter") == "q" for f in findings) or bool(findings)
        confirmed = doc.get("confirmed_count", 0) > 0
        return flagged, confirmed
    except Exception as e:  # noqa: BLE001
        print(f"    intellixss error on {name}: {e}", file=sys.stderr)
        return False, False


def run_dalfox(base: str, name: str, binpath: str, timeout: int) -> tuple[bool, bool]:
    url = _url(base, name)
    try:
        out = subprocess.run(
            [binpath, "url", url, "--format", "json", "--no-color",
             "--no-spinner", "--skip-bav", "--timeout", "10"],
            capture_output=True, text=True, timeout=timeout,
        ).stdout.strip()
        pocs = json.loads(out) if out else []
        real = [p for p in pocs if isinstance(p, dict) and p.get("type") in ("R", "V", "G")]
        flagged = len(real) > 0
        confirmed = any(p.get("type") == "V" for p in real)
        return flagged, confirmed
    except Exception as e:  # noqa: BLE001
        print(f"    dalfox error on {name}: {e}", file=sys.stderr)
        return False, False


# XSStrike has no machine-readable output. Its own verdict for a reflected
# vector is *Efficiency* — the percentage of a payload that survives the
# target's filtering; 100 means a fully-unfiltered, working payload. That is
# the fair bar: "reflections found" is only its recon line and fires on any
# echo, escaped or not, so keying on it would invent false positives XSStrike
# never claimed. A DOM finding is reported separately. XSStrike never executes
# a payload, so it never "confirms" (confirmed=False always).
_XSS_EFF100 = re.compile(r"Efficiency:\s*100\b")
_XSS_DOM = re.compile(r"Potentially vulnerable objects found|DOM XSS", re.I)


def run_xsstrike(base: str, name: str, xdir: str, timeout: int) -> tuple[bool, bool]:
    url = _url(base, name)
    try:
        out = subprocess.run(
            [sys.executable, "xsstrike.py", "-u", url, "--skip"],
            capture_output=True, text=True, timeout=timeout, cwd=xdir,
        ).stdout
        clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
        hit = bool(_XSS_EFF100.search(clean)) or bool(_XSS_DOM.search(clean))
        return hit, False
    except Exception as e:  # noqa: BLE001
        print(f"    xsstrike error on {name}: {e}", file=sys.stderr)
        return False, False


def score(results: dict) -> dict:
    tp = sum(1 for n in VULN if results.get(n, (False, False))[0])
    fp = sum(1 for n in CLEAN if results.get(n, (False, False))[0])
    confirmed = sum(1 for n in VULN if results.get(n, (False, False))[1])
    recall = tp / len(VULN) if VULN else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return {
        "true_positives": tp,
        "vuln_total": len(VULN),
        "false_positives": fp,
        "clean_total": len(CLEAN),
        "confirmed": confirmed,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "per_endpoint": {n: results.get(n, (False, False)) for n in ENDPOINTS},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--dalfox-bin", default="")
    ap.add_argument("--with-xsstrike", default="", metavar="DIR",
                    help="Path to an XSStrike checkout to also benchmark")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    srv = subprocess.Popen([sys.executable, str(HERE / "range.py"), str(args.port)])
    time.sleep(1.5)

    tools = {"intellixss": lambda n: run_intellixss(base, n, args.timeout)}
    if args.dalfox_bin:
        tools["dalfox"] = lambda n: run_dalfox(base, n, args.dalfox_bin, args.timeout)
    if args.with_xsstrike:
        tools["xsstrike"] = lambda n: run_xsstrike(base, n, args.with_xsstrike, args.timeout)

    report = {"endpoints": {n: ENDPOINTS[n][1] for n in ENDPOINTS},
              "vuln": VULN, "clean": CLEAN, "tools": {}}
    try:
        for tool, fn in tools.items():
            print(f"== {tool} ==")
            results = {}
            t0 = time.time()
            for name in ENDPOINTS:
                flagged, confirmed = fn(name)
                results[name] = (flagged, confirmed)
                mark = "VULN " if ENDPOINTS[name][0] else "clean"
                tag = "CONFIRMED" if confirmed else ("flag" if flagged else "-")
                print(f"  [{mark}] {name:22} -> {tag}")
            sc = score(results)
            sc["seconds"] = round(time.time() - t0, 1)
            report["tools"][tool] = sc
            print(f"  recall={sc['recall']} precision={sc['precision']} "
                  f"confirmed={sc['confirmed']}/{sc['vuln_total']} "
                  f"FP={sc['false_positives']} time={sc['seconds']}s")
    finally:
        srv.terminate()

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
