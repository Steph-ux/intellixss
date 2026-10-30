"""Render the 30-lab table for README.md, from benchmark/results.json.

The table is generated, never typed: a score a reader can check line by line is
the whole point of publishing it. Payloads are escaped so a ``|`` or a newline
cannot break the Markdown cell.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "docs" / "_table.md"

VERDICT = {"browser": "CONFIRMED", "static": "static-only", "reflection": "reflection"}


def cell(text: str, limit: int = 0) -> str:
    text = (text or "").replace("|", "\\|").replace("\n", " ")
    if limit and len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return f"`{text}`" if text else "-"


def main() -> None:
    rows = json.loads((ROOT / "benchmark" / "results.json").read_text(encoding="utf-8"))
    rows = sorted(rows, key=lambda r: r["i"])
    order = {"browser": 0, "static": 1, "reflection": 2}

    lines = [
        "| # | Lab | Difficulty | Verdict | Parameter | Context | Payload that fired |",
        "|---|-----|-----------|---------|-----------|---------|--------------------|",
    ]
    confirmed = static = clean = 0
    for r in rows:
        findings = r.get("findings") or []
        if not findings:
            verdict, f = "CLEAN", {}
            clean += 1
        else:
            f = sorted(findings, key=lambda x: order.get(x.get("verified_by"), 3))[0]
            verdict = VERDICT.get(f.get("verified_by"), "reflection")
            if verdict == "CONFIRMED":
                confirmed += 1
            elif verdict == "static-only":
                static += 1
        lines.append(
            f"| {r['i'] + 1} | {cell(r.get('fam'))} | {r.get('diff', '')} "
            f"| **{verdict}** | {cell(f.get('param'))} | {cell(f.get('ctx'))} "
            f"| {cell(f.get('payload'), 58)} |"
        )

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"docs/_table.md: {len(rows)} rows")
    print(f"confirmed={confirmed} static-only={static} clean={clean}")


if __name__ == "__main__":
    main()
