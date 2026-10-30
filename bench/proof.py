"""Render the proof document from the accumulated benchmark result.

Reads ``_psreport.json`` (written by the harness) and writes ``benchmark/`` with
a machine-readable copy, the per-lab table and one page per lab showing the
payload that fired, where it fired, and the request that reproduces it.

Instances are ephemeral: a PortSwigger lab expires within the hour, so the
instance host recorded here will no longer answer. It is kept because it is
what the scanner actually saw, and the lab id is what makes the run traceable.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "benchmark"
REPORT = ROOT / "_psreport.json"

VERDICT_NOTE = {
    "browser": "Execution observed in headless Chromium; the payload's own marker came back.",
    "static": "Source-to-sink analysis only: a path is proven, execution was not replayed.",
    "reflection": "Live markup reached the response; execution not observed.",
}


def verdict_of(row: dict) -> str:
    findings = row.get("findings") or []
    if any(f.get("verified_by") == "browser" for f in findings):
        return "CONFIRMED"
    if any(f.get("verified_by") == "static" for f in findings):
        return "static-only"
    if findings:
        return "reflection"
    return "CLEAN"


def best(finding_list: list) -> dict:
    """The row the report is graded on: browser proof beats a lead."""
    order = {"browser": 0, "static": 1, "reflection": 2}
    return sorted(finding_list, key=lambda f: order.get(f.get("verified_by"), 3))[0]


def table(rows: list) -> str:
    head = (
        "| # | Lab | Verdict | Evidence | Parameter | Context | Payload |\n"
        "|---|-----|---------|----------|-----------|---------|---------|\n"
    )
    body = []
    for row in sorted(rows, key=lambda r: r["i"]):
        findings = row.get("findings") or []
        verdict = verdict_of(row)
        if not findings:
            f = {}
        else:
            f = best(findings)
        payload = (f.get("payload") or "").replace("|", "\\|")
        body.append(
            f"| {row['i'] + 1} | {row.get('fam', '')} | **{verdict}** | "
            f"{f.get('verified_by') or '-'} | `{(f.get('param') or '-')}` | "
            f"`{(f.get('ctx') or '-')}` | `{payload}` |"
        )
    return head + "\n".join(body) + "\n"


def lab_page(row: dict) -> str:
    findings = row.get("findings") or []
    lines = [
        f"# Lab {row['i'] + 1} - {row.get('fam', '')}",
        "",
        f"- Path: `{row.get('path', '')}`",
        f"- Difficulty: {row.get('diff', '')}",
        f"- Instance: `{row.get('instance', '')}` (expired: labs live for about an hour)",
        f"- Verdict: **{verdict_of(row)}**",
        f"- Duration: {row.get('secs', 0)} s, {row.get('requests', 0)} requests",
        "",
    ]
    if not findings:
        lines += ["No finding. A lab with a known exploit that produced no finding "
                  "is a false negative and is listed as such in `SUMMARY.md`.", ""]
        return "\n".join(lines)

    lines += ["## Findings", ""]
    for f in findings:
        lines += [
            f"### `{f.get('param')}` - {f.get('ctx')} - {f.get('verified_by')}",
            "",
            f"- Severity: {f.get('sev')}",
            f"- Page: `{f.get('page')}`",
            f"- Payload:",
            "",
            "```html",
            f.get("payload") or "",
            "```",
            "",
            f"- {VERDICT_NOTE.get(f.get('verified_by'), '')}",
            "",
        ]
    return "\n".join(lines)


def main() -> None:
    rows = json.loads(REPORT.read_text(encoding="utf-8"))
    OUT.mkdir(exist_ok=True)
    labs_dir = OUT / "labs"
    if labs_dir.exists():
        shutil.rmtree(labs_dir)
    labs_dir.mkdir()

    shutil.copyfile(REPORT, OUT / "results.json")

    confirmed = sum(1 for r in rows if verdict_of(r) == "CONFIRMED")
    static = sum(1 for r in rows if verdict_of(r) == "static-only")
    clean = sum(1 for r in rows if verdict_of(r) == "CLEAN")
    total_secs = sum(r.get("secs") or 0 for r in rows)

    summary = [
        "# Benchmark results",
        "",
        f"{len(rows)} labs scanned, **{confirmed} confirmed in a browser**, "
        f"{static} static-only, {clean} clean.",
        "",
        f"Total scan time {total_secs / 60:.0f} min at the default 4 req/s.",
        "",
    ]
    if clean:
        summary += [
            "A `CLEAN` row on a lab that is vulnerable is a **false negative** and "
            "is treated as a defect, not as a passing grade.",
            "",
        ]
    summary += ["## Per-lab results", "", table(rows), ""]

    if confirmed != len(rows):
        summary += ["## Labs not confirmed in a browser", ""]
        for row in sorted(rows, key=lambda r: r["i"]):
            if verdict_of(row) == "CONFIRMED":
                continue
            findings = row.get("findings") or []
            why = (
                f"`{(best(findings).get('ctx'))}` via `{best(findings).get('param')}` - "
                f"{best(findings).get('verified_by')}"
                if findings
                else "no finding"
            )
            summary.append(f"- **{row['i'] + 1}. {row.get('fam')}** - {verdict_of(row)}: {why}")
        summary.append("")

    (OUT / "SUMMARY.md").write_text("\n".join(summary), encoding="utf-8")
    for row in rows:
        (labs_dir / f"lab-{row['i'] + 1:02d}.md").write_text(lab_page(row), encoding="utf-8")

    print(f"benchmark/: results.json, SUMMARY.md, {len(rows)} lab pages")
    print(f"confirmed={confirmed} static-only={static} clean={clean}")


if __name__ == "__main__":
    main()
