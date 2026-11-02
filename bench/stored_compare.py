"""Stored-XSS three-way: the class that most separates the scanners.

Each tool is given its best shot at the cross-page stored board
(`bench/stored_range.py`): a comment posted to /comment renders on /posts.

  IntelliXSS : -u / --write --crawl        (crawls, correlates write->render)
  Dalfox     : sxss /comment --trigger /posts   (its dedicated stored mode)
  XSStrike   : -u / --crawl                 (no stored mode exists)

Scores whether each DETECTS the stored XSS. XSStrike cannot by construction.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def _intellixss(base: str, timeout: int):
    try:
        out = subprocess.run(
            [sys.executable, str(ROOT / "intellixss.py"), "-u", base + "/",
             "--write", "--crawl", "--json", "-r", "50"],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        ).stdout
        doc = json.loads(out)
        doc = doc[0] if isinstance(doc, list) else doc
        stored = [f for f in doc.get("findings", []) if f.get("vulnerability_type", "").startswith("stored") or f.get("url", "").rstrip("/").endswith("posts")]
        if stored:
            return True, any(f.get("browser_confirmed") for f in stored)
        return False, False
    except Exception as e:  # noqa: BLE001
        print("  intellixss:", e, file=sys.stderr)
        return False, False


def _dalfox(base: str, binpath: str, timeout: int):
    """Give Dalfox both stored shots and report a completed result.

    Its dedicated ``sxss`` mode does not complete against this board (it is
    allowed to time out). Its normal ``url`` mode *does* complete — it posts to
    the write endpoint and checks the response — so it is the measured path: a
    completed run that finds nothing is a real miss, not a timeout. Both the
    write endpoint and the render page are tried.
    """
    # 1) sxss (dedicated stored) — best-effort; it tends to hang here.
    try:
        out = subprocess.run(
            [binpath, "sxss", base + "/comment", "-d", "comment=DALFOXSS",
             "--request-method", "POST", "--trigger", base + "/posts",
             "--format", "json", "--no-color", "--no-spinner", "--timeout", "10"],
            capture_output=True, text=True, timeout=min(timeout, 60),
        ).stdout.strip()
        pocs = json.loads(out) if out else []
        real = [p for p in pocs if isinstance(p, dict) and p.get("type") in ("R", "V", "G")]
        if real:
            return True, any(p.get("type") == "V" for p in real)
    except subprocess.TimeoutExpired:
        print("  dalfox sxss: did not complete (timeout)", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print("  dalfox sxss:", e, file=sys.stderr)

    # 2) url mode — completes; a 0-poc result here is a measured miss.
    for ep, data, method in (("/comment", "comment=FUZZ", "POST"), ("/posts", None, "GET"), ("/", None, "GET")):
        cmd = [binpath, "url", base + ep, "--format", "json", "--no-color",
               "--no-spinner", "--skip-bav", "--timeout", "10"]
        if data:
            cmd += ["-d", data, "-X", method]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=min(timeout, 80)).stdout.strip()
            pocs = json.loads(out) if out else []
            real = [p for p in pocs if isinstance(p, dict) and p.get("type") in ("R", "V", "G")]
            if real:
                return True, any(p.get("type") == "V" for p in real)
        except Exception as e:  # noqa: BLE001
            print(f"  dalfox url {ep}:", e, file=sys.stderr)
    return False, False  # completed (url mode) with no detection — a measured miss


def _xsstrike(base: str, xdir: str, timeout: int):
    try:
        out = subprocess.run(
            [sys.executable, "xsstrike.py", "-u", base + "/", "--crawl"],
            capture_output=True, text=True, timeout=timeout, cwd=xdir,
        ).stdout
        clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
        # XSStrike has no stored workflow; the only way it "finds" this is if it
        # happened to land a working reflected payload, which this board never
        # echoes. Efficiency 100 anywhere is its success marker.
        return bool(re.search(r"Efficiency:\s*100\b", clean)), False
    except Exception as e:  # noqa: BLE001
        print("  xsstrike:", e, file=sys.stderr)
        return False, False


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8910)
    ap.add_argument("--dalfox-bin", default="")
    ap.add_argument("--with-xsstrike", default="")
    ap.add_argument("--timeout", type=int, default=180)
    a = ap.parse_args()
    base = f"http://127.0.0.1:{a.port}"
    srv = subprocess.Popen([sys.executable, str(HERE / "stored_range.py"), str(a.port)])
    time.sleep(1.5)
    res = {}
    try:
        print("== intellixss =="); res["intellixss"] = _intellixss(base, a.timeout)
        print("  ->", res["intellixss"])
        if a.dalfox_bin:
            print("== dalfox (sxss) =="); res["dalfox"] = _dalfox(base, a.dalfox_bin, a.timeout)
            print("  ->", res["dalfox"])
        if a.with_xsstrike:
            print("== xsstrike =="); res["xsstrike"] = _xsstrike(base, a.with_xsstrike, a.timeout)
            print("  ->", res["xsstrike"])
    finally:
        srv.terminate()
    for t, (found, conf) in res.items():
        print(f"{t:12} stored: {'detected' if found else 'MISSED'}"
              f"{' (confirmed)' if conf else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
