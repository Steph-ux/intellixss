"""Render the per-lab benchmark table from the accumulated report."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

with open(ROOT / "_psreport.json", encoding="utf-8") as fh:
    rows = json.load(fh)

rows.sort(key=lambda r: r["i"])
print(f"{'#':>2}  {'S':<10} {'verdict':<10} {'secs':>6} {'req':>4}  {'param':<10} {'ctx':<20} {'by':<10} payload")
print("-" * 130)
for r in rows:
    fs = r.get("findings") or []
    browser = [f for f in fs if f.get("verified_by") == "browser"]
    if browser:
        verdict = "CONFIRMED"
        f = browser[0]
    elif any(f.get("verified_by") == "static" for f in fs):
        verdict = "static-only"
        f = [x for x in fs if x.get("verified_by") == "static"][0]
    elif fs:
        verdict = "reflection"
        f = fs[0]
    else:
        verdict = "CLEAN"
        f = {}
    secs = r.get("secs")
    print(
        f"{r['i']:>2}  {r.get('diff','')[:10]:<10} {verdict:<10} "
        f"{secs if secs is not None else 0:>6.1f} "
        f"{r.get('requests',0):>4}  {(f.get('param') or '-')[:10]:<10} "
        f"{(f.get('ctx') or '-')[:20]:<20} {(f.get('verified_by') or '-')[:10]:<10} "
        f"{(f.get('payload') or '')[:52]!r}"
    )

tot = sum((r.get("secs") or 0) for r in rows)
conf = sum(1 for r in rows if any(f.get("verified_by") == "browser" for f in (r.get("findings") or [])))
static = sum(
    1
    for r in rows
    if not any(f.get("verified_by") == "browser" for f in (r.get("findings") or []))
    and any(f.get("verified_by") == "static" for f in (r.get("findings") or []))
)
print("-" * 130)
print(f"labs={len(rows)} confirmed={conf} static-only={static} total={tot:.0f}s")
