"""Render benchmark/comparison.json into a human-readable markdown report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

TOOL_LABEL = {
    "intellixss": "IntelliXSS",
    "dalfox": "Dalfox",
    "xsstrike": "XSStrike",
}


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "benchmark/comparison.json")
    data = json.loads(src.read_text(encoding="utf-8"))
    tools = data["tools"]
    vuln = data["vuln"]
    clean = data["clean"]
    endpoints = data["endpoints"]

    out = []
    out.append("# Head-to-head: IntelliXSS vs Dalfox vs XSStrike\n")
    out.append(
        "All scanners were pointed at the identical local range "
        "(`bench/range.py`): seven vulnerable endpoints across distinct "
        "contexts and three clean controls that reflect safely or not at all. "
        "Reproduce with `python bench/compare.py` (see below).\n"
    )

    # Summary table.
    out.append("## Scorecard\n")
    out.append(
        "| Scanner | Recall (found/total) | Confirmed by execution | "
        "False positives | Precision | Time |"
    )
    out.append("|---|---|---|---|---|---|")
    for tool, sc in tools.items():
        label = TOOL_LABEL.get(tool, tool)
        out.append(
            f"| {label} | {sc['true_positives']}/{sc['vuln_total']} "
            f"({sc['recall']:.0%}) | {sc['confirmed']}/{sc['vuln_total']} | "
            f"{sc['false_positives']}/{sc['clean_total']} | "
            f"{sc['precision']:.0%} | {sc['seconds']}s |"
        )
    out.append("")
    out.append(
        "*Confirmed by execution* means the payload was proven to run "
        "(IntelliXSS: the unique marker came back in a headless browser; "
        "Dalfox: a `V`/verified PoC). A plain *found* is reflection only.\n"
    )

    # Per-endpoint matrix.
    out.append("## Per-endpoint\n")
    header = "| Endpoint | Context | Vulnerable? | " + " | ".join(
        TOOL_LABEL.get(t, t) for t in tools
    ) + " |"
    out.append(header)
    out.append("|---" * (3 + len(tools)) + "|")
    for name in endpoints:
        is_vuln = name in vuln
        row = [name, f"`{endpoints[name]}`", "yes" if is_vuln else "no (control)"]
        for tool in tools:
            flagged, confirmed = tools[tool]["per_endpoint"][name]
            if confirmed:
                cell = "CONFIRMED"
            elif flagged:
                cell = "found" if is_vuln else "**false +**"
            else:
                cell = "miss" if is_vuln else "ok"
            row.append(cell)
        out.append("| " + " | ".join(row) + " |")
    out.append("")

    # Reproduce.
    out.append("## Reproduce\n")
    out.append("```bash")
    out.append("# 1. Dalfox (Go)")
    out.append("GOBIN=$PWD/bin go install github.com/hahwul/dalfox/v2@latest")
    out.append("# 2. XSStrike (Python)")
    out.append("git clone --depth 1 https://github.com/s0md3v/XSStrike.git")
    out.append("pip install tld fuzzywuzzy")
    out.append("# 3. Run the three-way benchmark")
    out.append(
        "python bench/compare.py --dalfox-bin ./bin/dalfox "
        "--with-xsstrike ./XSStrike --out benchmark/comparison.json"
    )
    out.append("python bench/comparison_md.py benchmark/comparison.json")
    out.append("```")

    dest = Path("benchmark/comparison.md")
    dest.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
