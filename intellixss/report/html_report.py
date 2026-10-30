"""Professional HTML report generator.

Section order matches how a reader actually consumes a pentest report:
verdict → findings (with proof, CVSS, remediation) → diagnostics → metadata.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from intellixss.models import ScanResult, XSSFinding

from intellixss.models import reproduce_command

_SEV_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}

_VERIFIED_CLASS = {"CONFIRMED": "ok", "REFLECTED": "warn", "STATIC": "info"}


def _remediation(vtype: str, ctx: str) -> str:
    if vtype.startswith("stored"):
        return (
            "Encode on render with a context-aware escaper and sanitize stored "
            "content with a vetted HTML sanitizer. Add CSP with nonces."
        )
    if vtype == "dom":
        return "Use textContent or a sanitizer before innerHTML; allowlist fragments."
    if vtype in ("json_body", "graphql"):
        return "Encode at the rendering layer; serve JSON with an explicit content type."
    if vtype == "file_upload_xss":
        return (
            "Serve uploads from a separate origin with Content-Disposition: attachment; "
            "reject SVG/HTML types."
        )
    if vtype == "open_redirect_xss":
        return "Allowlist redirect targets; never pass user input to location.href."
    if ctx.startswith("js"):
        return "JSON-encode and escape </script>; avoid inline script with user data."
    if ctx.startswith("html_attr"):
        return "HTML-attribute-encode all dynamic attribute values and always quote them."
    return "Context-aware output encoding for text nodes, plus a strict CSP with nonces."


def _finding_block(i: int, f: "XSSFinding") -> str:
    cvss = f.cvss
    sev = f.severity.value
    vclass = _VERIFIED_CLASS.get(f.verified_label, "")
    bypass = ", ".join(x.label for x in f.filters_bypassed) or "—"
    marker = f"<div class='kv'><span>Marker</span><code>{html.escape(f.marker)}</code></div>" if f.marker else ""
    trigger = f"<div class='kv'><span>Trigger</span><code>{html.escape(f.trigger)}</code></div>" if f.trigger else ""
    waf = f"<div class='kv'><span>WAF</span><code>{html.escape(f.waf)}</code></div>" if f.waf else ""

    return f"""
    <article class="finding">
      <header>
        <span class="badge {_SEV_CLASS.get(sev, '')}">{html.escape(sev.upper())}</span>
        <span class="badge cvss">CVSS {cvss['score']:.1f}</span>
        <span class="badge {vclass}">{html.escape(f.verified_label)}</span>
        <strong>#{i} {html.escape(f.vulnerability_type)}</strong>
      </header>
      <div class="kv"><span>URL</span><code class="break">{html.escape(f.url)}</code></div>
      <div class="kv"><span>Parameter</span><code>{html.escape(f.parameter)} ({html.escape(f.method)})</code></div>
      <div class="kv"><span>Context</span><code>{html.escape(f.context.label)}</code></div>
      <div class="kv"><span>Payload</span><code class="break payload">{html.escape(f.payload)}</code></div>
      {marker}{trigger}{waf}
      <div class="kv"><span>Bypassed</span><code>{html.escape(bypass)}</code></div>
      <div class="kv"><span>Vector</span><code class="dim">{html.escape(cvss['vector'])}</code></div>
      <div class="kv"><span>Evidence</span><code class="break">{html.escape(f.evidence or '')}</code></div>
      <div class="kv"><span>Reproduce</span><code class="break payload">{html.escape(reproduce_command(f))}</code></div>
      <div class="fix"><span>Remediation</span>{html.escape(_remediation(f.vulnerability_type, f.context.value))}</div>
    </article>"""


def _diag_rows(diags: List) -> str:
    out = []
    for d in diags[:100]:
        sig = ", ".join(d.signals[:6]) if d.signals else ""
        out.append(
            "<tr>"
            f"<td><code>{html.escape(d.reason.value)}</code></td>"
            f"<td>{d.status if d.status is not None else ''}</td>"
            f"<td class='break'>{html.escape((d.detail or '')[:300])}"
            + (f"<div class='dim'>{html.escape(sig)}</div>" if sig else "")
            + "</td>"
            f"<td>{html.escape(d.suggestion or '')}</td>"
            "</tr>"
        )
    return "".join(out)


def write_html_report(result: "ScanResult", path: str, version: str = "3.3.0") -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    findings = result.findings
    bc = len(result.confirmed)
    counts = result.counts_by_severity()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    ordered = sorted(
        findings, key=lambda f: (not f.browser_confirmed, -f.cvss["score"], f.url)
    )
    blocks = "".join(_finding_block(i, f) for i, f in enumerate(ordered, 1))
    diag = _diag_rows(result.diagnoses)

    if findings:
        verdict = (
            f"{len(findings)} finding(s) &middot; {bc} browser-confirmed"
            + (
                f" &middot; max severity <span class='badge {_SEV_CLASS.get(result.max_severity.value, '')}'>"
                f"{result.max_severity.value.upper()}</span>"
                if result.max_severity
                else ""
            )
        )
        verdict_cls = "danger"
    else:
        verdict = "No XSS confirmed"
        verdict_cls = "safe"

    # A finding that no browser replay proved is a lead, not a result. Saying so
    # next to the headline is the difference between a report a client can act
    # on and one that overstates what was demonstrated.
    if findings and not bc:
        caveat = (
            "<div class='caveat'>No execution was proven in a browser. Every "
            "finding below is a lead: live markup reached the response, or a "
            "source reaches a sink in source analysis, but no replay observed "
            "the payload run. Treat them as candidates to confirm by hand "
            "before reporting them as exploitable.</div>"
        )
    elif bc and bc < len(findings):
        caveat = (
            f"<div class='caveat'>{len(findings) - bc} finding(s) below are "
            f"unconfirmed leads; {bc} carry browser proof.</div>"
        )
    else:
        caveat = ""

    sev_cards = "".join(
        f"<div class='card {_SEV_CLASS.get(s, '')}'><div class='n'>{counts.get(s, 0)}</div>"
        f"<div class='l'>{s.upper()}</div></div>"
        for s in ("critical", "high", "medium", "low")
        if counts.get(s, 0) or s in ("high", "critical")
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IntelliXSS — {html.escape(result.target_url)}</title>
  <style>
    :root {{ --bg:#0b1020; --card:#141b2d; --text:#e8eefc; --muted:#9aa8c7;
             --ok:#3ddc97; --warn:#f0c14b; --accent:#6ea8fe; --border:#243049;
             --crit:#ff5c7a; --high:#ff8a4c; --med:#f0c14b; --low:#6ea8fe; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
           background: linear-gradient(160deg,#0b1020,#121a30 40%,#0d1424);
           color: var(--text); line-height:1.5; }}
    .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px 72px; }}
    h1 {{ font-size: 1.5rem; margin: 0 0 4px; letter-spacing:-.01em; }}
    h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing:.08em;
          margin: 36px 0 14px; color: var(--accent); font-weight: 600; }}
    .sub {{ color: var(--muted); font-size: .88rem; margin-bottom: 22px; }}
    .verdict {{ border-radius:14px; padding:18px 20px; font-size:1.15rem; font-weight:600;
                border:1px solid var(--border); margin-bottom: 20px; }}
    .verdict.danger {{ background: rgba(255,92,122,.10); border-color: rgba(255,92,122,.35); }}
    .verdict.safe {{ background: rgba(61,220,151,.08); border-color: rgba(61,220,151,.3); }}
    .cards {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(130px,1fr)); gap:12px; }}
    .card {{ background: var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 16px; }}
    .card .n {{ font-size: 1.7rem; font-weight: 700; }}
    .card .l {{ color: var(--muted); font-size: .78rem; letter-spacing:.06em; }}
    .card.sev-critical .n {{ color: var(--crit); }}
    .card.sev-high .n {{ color: var(--high); }}
    .card.sev-medium .n {{ color: var(--med); }}
    .card.sev-low .n {{ color: var(--low); }}
    .card.zero .n {{ color: var(--warn); }}
    .caveat {{ border-radius:12px; padding:12px 16px; margin-bottom:20px;
               background: rgba(240,193,75,.10); border:1px solid rgba(240,193,75,.35);
               color: var(--warn); font-size:.9rem; }}
    .finding {{ background: var(--card); border:1px solid var(--border); border-radius:14px;
                padding: 18px 20px; margin-bottom: 16px; }}
    .finding header {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center;
                       margin-bottom: 14px; font-size: .95rem; }}
    .badge {{ display:inline-block; padding:2px 9px; border-radius:999px;
              font-size:.72rem; font-weight:700; letter-spacing:.04em; }}
    .badge.sev-critical {{ background: rgba(255,92,122,.18); color: var(--crit); }}
    .badge.sev-high {{ background: rgba(255,138,76,.18); color: var(--high); }}
    .badge.sev-medium {{ background: rgba(240,193,75,.18); color: var(--med); }}
    .badge.sev-low, .badge.info {{ background: rgba(110,168,254,.18); color: var(--low); }}
    .badge.cvss {{ background:#1c2740; color: var(--text); }}
    .badge.ok {{ background: rgba(61,220,151,.18); color: var(--ok); }}
    .badge.warn {{ background: rgba(240,193,75,.18); color: var(--warn); }}
    .kv {{ display:grid; grid-template-columns: 110px 1fr; gap:10px; padding:5px 0;
           border-bottom: 1px dashed rgba(36,48,73,.9); }}
    .kv:last-of-type {{ border-bottom: none; }}
    .kv > span {{ color: var(--muted); font-size:.82rem; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .82rem; color:#cfe0ff; }}    code.payload {{ color: var(--warn); }}
    .break {{ word-break: break-all; }}
    .dim {{ color: var(--muted); }}
    .fix {{ margin-top: 12px; padding: 10px 12px; border-radius:10px;
            background: rgba(61,220,151,.07); border:1px solid rgba(61,220,151,.2);
            font-size:.88rem; }}
    .fix span {{ display:block; color: var(--ok); font-weight:700; font-size:.75rem;
                 letter-spacing:.08em; text-transform:uppercase; margin-bottom:4px; }}
    table {{ width:100%; border-collapse: collapse; background: var(--card);
             border:1px solid var(--border); border-radius:12px; overflow:hidden; }}
    th, td {{ text-align:left; padding:9px 12px; border-bottom:1px solid var(--border);
              vertical-align: top; font-size: .85rem; }}
    th {{ background:#1a2338; color: var(--muted); font-weight:600; }}
    tr:last-child td {{ border-bottom:0; }}
    .empty {{ color: var(--muted); }}
    footer {{ margin-top: 36px; color: var(--muted); font-size: .8rem; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>IntelliXSS Scan Report</h1>
    <div class="sub">
      Target <code>{html.escape(result.target_url)}</code><br/>
      Generated {now} &middot; Engine v{html.escape(version)}
      {" &middot; WAF <code>" + html.escape(result.waf) + "</code>" if result.waf else ""}
    </div>

    <div class="verdict {verdict_cls}">{verdict}</div>
    {caveat}

    <div class="cards">
      {sev_cards}
      <div class="card {'' if bc else 'zero'}"><div class="n">{bc}</div><div class="l">BROWSER-CONFIRMED</div></div>
      <div class="card"><div class="n">{result.targets_tested}</div><div class="l">TARGETS</div></div>
      <div class="card"><div class="n">{result.stats.requests}</div><div class="l">REQUESTS</div></div>
      <div class="card"><div class="n">{result.stats.duration:.0f}s</div><div class="l">DURATION</div></div>
    </div>

    <h2>Findings</h2>
    {blocks if blocks else "<p class='empty'>No findings.</p>"}

    <h2>Diagnostics</h2>
    {
        "<table><thead><tr><th>Reason</th><th>HTTP</th><th>Detail</th><th>Suggestion</th></tr></thead><tbody>"
        + diag + "</tbody></table>"
        if diag else "<p class='empty'>None.</p>"
    }

    <footer>
      IntelliXSS — authorized testing only. CONFIRMED means a headless browser
      observed execution proving the injected marker; REFLECTED means structural
      HTML/JS evidence survived but execution was not replayed; STATIC means
      source→sink analysis only.
    </footer>
  </div>
</body>
</html>
"""
    out.write_text(doc, encoding="utf-8")
    return str(out)
