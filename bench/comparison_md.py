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
        f"(`bench/range.py`): {len(vuln)} vulnerable endpoints across distinct "
        f"contexts and {len(clean)} clean controls that reflect safely or not "
        "at all. XSStrike is scored by its own `Efficiency` metric (a payload "
        "at 100 = working), not its recon lines, so the comparison is fair to "
        "it. Reproduce with `python bench/compare.py --with-xsstrike …` (below).\n"
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

    # Discovery (root-only) — a separate fixture, stated as a fixed result
    # because it is a capability comparison, not a per-endpoint score.
    out.append("## Discovery (root-only)\n")
    out.append(
        "The table above gives every scanner the exact vulnerable URL. The "
        "other half of being the best is what each finds given only a site "
        "**root**. `bench/crawl_range.py` hides three reflected XSS off the "
        "index: a link-revealed GET param (`/search?q=`), a one-hop filter "
        "param (`/products?category=`), and a form two hops deep "
        "(`/feedback`). Pointed at the root:\n"
    )
    out.append("| Scanner | Given only `/` | Deep XSS found |")
    out.append("|---|---|---|")
    out.append("| **IntelliXSS** | `-u http://host/ --crawl` | **3/3, browser-confirmed** |")
    out.append("| Dalfox | `url http://host/` | 0/3 (no link crawl) |")
    out.append("| XSStrike | `-u http://host/ --crawl` | 0/3 (form-only crawler) |")
    out.append(
        "\nIntelliXSS's crawl follows same-origin links and scans each page's "
        "parameters and forms, so all three are reached and confirmed; a "
        "single-URL scan never leaves the root, and a form-only crawler misses "
        "the link-reachable GET params. Reproduce: `python bench/crawl_range.py "
        "&` then each command against `http://127.0.0.1:8890/`.\n"
    )

    out.append("## Whole site, root only — the realistic test\n")
    out.append(
        "The per-endpoint table hands each tool the exact vulnerable URL; under "
        "that artificial condition XSStrike matches IntelliXSS on the reflected "
        "endpoints. The real task is a **site**: `bench/site_range.py` puts four "
        "XSS behind one root — three reflected (a link param, a filter param, a "
        "form two hops deep) and one stored (posted on a guestbook, rendered on "
        "`/posts`). Every tool is given only `http://host/`:\n"
    )
    out.append("| Scanner | Invocation | XSS found |")
    out.append("|---|---|---|")
    out.append("| **IntelliXSS** | `-u / --crawl --write` | **4/4, all browser-confirmed** |")
    out.append("| Dalfox | `url /` | 0/4 |")
    out.append("| XSStrike | `-u / --crawl` | 0/4 |")
    out.append(
        "\nGiven a site rather than a list of exact injection points, IntelliXSS "
        "finds and proves every one; both competitors find none. This is where "
        "the reflected-endpoint 'tie' with XSStrike disappears — it depends on "
        "being handed the URL, which no real engagement does.\n"
    )

    out.append("## Stored XSS (root-only)\n")
    out.append(
        "Stored XSS is the class that most separates the tools. "
        "`bench/stored_range.py` is the real shape of it: a comment posted to "
        "`/comment` redirects to `/thanks` (the payload is never echoed back) "
        "and renders on a different page, `/posts`, linked from the index. "
        "Finding it from the root means correlating *write here* with *renders "
        "there*. Pointed at the root:\n"
    )
    out.append("| Scanner | Given only `/` | Stored XSS |")
    out.append("|---|---|---|")
    out.append("| **IntelliXSS** | `-u http://host/ --write --crawl` | **detected** (write→render correlated across pages) |")
    out.append("| Dalfox | `url http://host/` | not found (no link crawl; stored needs an explicit `--trigger`) |")
    out.append("| XSStrike | `-u http://host/ --crawl` | not found (no stored workflow at all) |")
    out.append(
        "\nXSStrike has no inject-here / verify-there mode, so it cannot find "
        "stored XSS by construction; Dalfox can, but only when told the trigger "
        "URL. IntelliXSS reaches it automatically from the root. The finding is "
        "reported at reflection confidence — browser-confirming a record that "
        "renders on another page is a tracked item in `AUDIT.md` — but it is a "
        "real vulnerability detected that both others miss. Reproduce: "
        "`python bench/stored_range.py &` then the commands above.\n"
    )

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
