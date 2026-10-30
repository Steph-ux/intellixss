"""Generate the README screenshots from real scanner output.

Two images:

  docs/console.png  the scanner's own console output, captured from a real
                    run against a live PortSwigger lab, rendered as a terminal.
  docs/report.png   the HTML report produced by the same run.

The console image is produced by running the scanner for real and rendering
its captured stdout. Nothing in the image is hand-written: if the scanner
output changes, regenerate and the image follows.
"""
from __future__ import annotations

import asyncio
import html
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOCS = ROOT / "docs"
LAB = "cross-site-scripting/reflected/lab-html-context-nothing-encoded"


def launch_lab() -> str | None:
    """Launch the lab through the bench harness, reusing its session."""
    sys.path.insert(0, str(ROOT))
    import _psbench  # noqa: PLC0415 - harness is deliberately import-lazy

    return _psbench.launch(LAB)


def run_scanner(url: str) -> str:
    proc = subprocess.run(
        [
            sys.executable,
            "intellixss.py",
            "-u",
            url + "/",
            "--html",
            str(DOCS / "_report.html"),
            "-r",
            "4",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    return proc.stdout + proc.stderr


TERMINAL_HTML = """<!doctype html>
<meta charset="utf-8">
<style>
  body {{ margin:0; background:#0b0f17; }}
  .win {{ font: 13px/1.45 "Cascadia Mono", Consolas, monospace;
          background:#0d1117; color:#c9d1d9; border-radius:10px;
          padding:14px 16px 18px; width:1180px; box-sizing:border-box; }}
  .bar {{ display:flex; gap:7px; margin-bottom:12px; }}
  .dot {{ width:11px; height:11px; border-radius:50%; }}
  pre {{ margin:0; white-space:pre-wrap; word-break:break-word; }}
</style>
<div class="win">
  <div class="bar">
    <span class="dot" style="background:#ff5f57"></span>
    <span class="dot" style="background:#febc2e"></span>
    <span class="dot" style="background:#28c840"></span>
  </div>
  <pre>{body}</pre>
</div>
"""


def png(page_body: str, out: Path, width: int = 1212) -> None:
    from playwright.sync_api import sync_playwright

    tmp = DOCS / "_shot.html"
    tmp.write_text(page_body, encoding="utf-8")
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": width, "height": 800},
                        device_scale_factor=2)
        pg.goto(tmp.as_uri())
        pg.screenshot(path=str(out), full_page=True)
        b.close()
    tmp.unlink(missing_ok=True)


def main() -> int:
    DOCS.mkdir(exist_ok=True)
    url = launch_lab()
    if not url:
        print("no lab instance - aborting rather than faking an image")
        return 1
    print(f"lab: {url}")

    output = run_scanner(url)
    # Strip ANSI colour so the capture reads in one style, and the absolute
    # path of this machine: where the report was written is not the target's
    # business, and a public README should not carry a developer's directory.
    import re

    clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
    clean = re.sub(
        r"^HTML report\s+->.*$", "HTML report  -> docs/report.html", clean,
        flags=re.MULTILINE,
    )
    clean = clean.replace(str(ROOT), ".")
    body = html.escape(clean).replace("\n", "<br>")
    png(TERMINAL_HTML.format(body=body), DOCS / "console.png")
    print(f"docs/console.png ({len(clean.splitlines())} lines)")

    report = DOCS / "_report.html"
    if report.exists():
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1200, "height": 900},
                            device_scale_factor=2)
            pg.goto(report.as_uri())
            pg.screenshot(path=str(DOCS / "report.png"), full_page=True)
            b.close()
        print("docs/report.png")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(asyncio.to_thread(main)))
