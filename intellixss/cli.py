"""CLI entry for IntelliXSS — rich, readable, scriptable.

Design goals
------------
* **Answer first.** The findings table leads; diagnosis noise comes after.
* **Severity colour, not wall of text.** CVSS score + severity badge per finding.
* **Honest states.** CONFIRMED (browser proved execution) vs REFLECTED (static
  evidence only) vs STATIC (DOM source→sink analysis) are visually distinct.
* **Never crash on a broken terminal.** Falls back to plain text when rich is
  unavailable or output is redirected (``--json`` / pipes stay clean).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init

from intellixss import __version__
from intellixss.auth import AuthConfig, parse_header_string
from intellixss.config import Config
from intellixss.models import ScanResult, Severity, XSSFinding, reproduce_command
from intellixss.report.html_report import write_html_report
from intellixss.scanner.orchestrator import Scanner, result_to_json

colorama_init(autoreset=True)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:  # pragma: no cover - optional
    HAS_RICH = False


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

VERIFIED_STYLE = {
    "CONFIRMED": "bold green",
    "REFLECTED": "yellow",
    "STATIC": "magenta",
}


# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="intellixss",
        description=(
            f"IntelliXSS v{__version__} — HTML5-aware XSS scanner. "
            "Context detection, marker-causal browser confirmation, "
            "stored/JSON/GraphQL/upload plugins, encoding escalation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  intellixss -u https://xss-game.appspot.com/level1\n"
            "  intellixss -u https://target/ --deep -w 6 -r 6 --html report.html\n"
            "  intellixss -u https://app/ --cookie 'session=abc' --no-browser\n"
        ),
    )
    p.add_argument("-u", "--url", help="Target URL (path-scoped discovery)")
    p.add_argument("-l", "--list", help="File with URLs (one per line)")

    out = p.add_argument_group("reporting")
    out.add_argument("-o", "--output", help="Write JSON report to path")
    out.add_argument("--html", help="Write HTML report to path")
    out.add_argument(
        "--json", action="store_true", help="Print JSON to stdout and nothing else"
    )

    perf = p.add_argument_group("performance")
    perf.add_argument("-r", "--rate", type=float, default=4.0, help="Req/s (default 4)")
    perf.add_argument("-w", "--workers", type=int, default=4, help="Workers (default 4)")
    perf.add_argument("--timeout", type=float, default=12.0, help="Per-request timeout (s)")
    perf.add_argument(
        "--max-payloads",
        type=int,
        default=25,
        help="Payloads per parameter per stage (default 25)",
    )
    perf.add_argument(
        "--retries", type=int, default=2, help="Transient network retries (default 2)"
    )
    perf.add_argument(
        "--no-adaptive",
        dest="adaptive",
        action="store_false",
        default=True,
        help="Disable adaptive throttling (back off on 429/503)",
    )

    scan = p.add_argument_group("scanning")
    scan.add_argument(
        "-a",
        "--aggressive",
        action="store_true",
        help="Keep trying after a hit (all payloads, all params)",
    )
    scan.add_argument(
        "--guess-params",
        action="store_true",
        help="Try conventional parameter names the page never links to",
    )
    scan.add_argument("-v", "--verbose", action="store_true", help="Debug output")
    scan.add_argument("-s", "--silent", action="store_true", help="Only findings")
    scan.add_argument(
        "--browser", dest="use_browser", action="store_true", default=True
    )
    scan.add_argument(
        "--no-browser",
        dest="use_browser",
        action="store_false",
        help="Skip Playwright confirmation (faster, less proof)",
    )
    scan.add_argument(
        "--deep",
        action="store_true",
        help="Also run header, redirect, JSON, GraphQL and upload plugins",
    )
    scan.add_argument(
        "--write",
        dest="writes",
        action="store_true",
        help=(
            "Allow POST/PUT/PATCH/DELETE payloads (stored, upload, JSON and "
            "GraphQL sinks). Off by default: a scan only reads the target"
        ),
    )
    scan.add_argument(
        "--max-confirm",
        type=int,
        default=12,
        help="Max browser navigations per host (default 12)",
    )

    auth = p.add_argument_group("authentication")
    auth.add_argument("--cookie", default="", help="Cookie string: a=b; c=d")
    auth.add_argument("--bearer", default="", help="Bearer / JWT token")
    auth.add_argument("--basic", default="", help="HTTP Basic user:pass")
    auth.add_argument(
        "--header",
        action="append",
        default=[],
        help="Custom header 'Name: value' (repeatable)",
    )
    auth.add_argument("--login-url", default="", help="Form login URL path or full URL")
    auth.add_argument("--username", default="", help="Form login username")
    auth.add_argument("--password", default="", help="Form login password")
    auth.add_argument("--username-field", default="username")
    auth.add_argument("--password-field", default="password")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ----------------------------------------------------------------------
# rendering
# ----------------------------------------------------------------------


def _console() -> "Console":
    # rich enters "legacy Windows" mode inside the PowerShell 5 host, where it
    # writes styled text straight to a cp1252 stream. The tool's own strings
    # carry "-", "..." and "->" as their UTF-8 forms, so the first styled line
    # under that host raised UnicodeEncodeError and killed the scan after the
    # work was done. Opting out keeps rich emitting ANSI instead, which the
    # host passes through unchanged.
    return Console(
        force_terminal=sys.stdout.isatty(),
        force_interactive=False,
        legacy_windows=False,
        soft_wrap=False,
        highlight=False,
    )


def render_summary(result: ScanResult, console: "Console") -> None:
    """The bottom line: how many findings, how bad, how solid."""
    counts = result.counts_by_severity()
    confirmed = len(result.confirmed)
    total = len(result.findings)

    if not total:
        head = Text("No XSS confirmed", style="bold yellow")
        body = Text()
        body.append(f"{result.targets_tested} target(s) tested, ")
        body.append(f"{len(result.diagnoses)} block diagnosis(es).\n")
        if result.waf:
            body.append(f"WAF detected: {result.waf}\n", style="yellow")
        body.append(
            "Nothing executed. See the diagnosis table below for what each "
            "parameter hit (encoding, stripping, WAF, no reflection).",
            style="dim",
        )
        console.print(Panel(body, title=head, border_style="yellow"))
        return

    head = Text(f"{total} finding(s)", style="bold")
    if confirmed:
        head.append(f" — {confirmed} browser-confirmed", style="bold green")
    else:
        # Every finding below is a lead. Saying it in the headline keeps the
        # count from being read as proof.
        head.append(" — none browser-confirmed (leads only)", style="bold yellow")
    if result.max_severity:
        head.append("   max ")
        head.append(
            f" {result.max_severity.value.upper()} ",
            style=SEVERITY_STYLE[result.max_severity],
        )

    body = Text()
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev.value, 0)
        if n:
            body.append(f" {sev.value.upper()} ", style=SEVERITY_STYLE[sev])
            body.append(f" {n}   ")
    body.append("\n\n", style="")
    body.append(
        f"targets={result.targets_tested}  requests={result.stats.requests}  "
        f"payloads={result.stats.payloads_sent}  "
        f"duration={result.stats.duration:.1f}s  "
        f"({result.stats.req_per_sec}/s)",
        style="dim",
    )
    console.print(Panel(body, title=head, border_style="green"))


def render_findings(result: ScanResult, console: "Console", verbose: bool = False) -> None:
    if not result.findings:
        return

    table = Table(
        title="Findings",
        title_style="bold",
        show_lines=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", width=3, justify="right")
    table.add_column("Sev", width=9)
    table.add_column("CVSS", width=5, justify="center")
    table.add_column("Proof", width=10)
    table.add_column("Type", width=20)
    table.add_column("Param", width=14)
    table.add_column("Context / endpoint", ratio=3)

    ordered = sorted(
        result.findings,
        key=lambda f: (not f.browser_confirmed, -f.cvss["score"], f.url),
    )
    for i, f in enumerate(ordered, 1):
        sev = f.severity
        endpoint = Text()
        endpoint.append(f.parameter, style="bold")
        endpoint.append(f"  {f.method}  ", style="dim")
        endpoint.append(f.url, style="cyan")
        endpoint.append(f"\n{f.context.label}", style="dim")
        if f.waf:
            endpoint.append(f"  ·  via {f.waf}", style="yellow")
        if f.trigger:
            endpoint.append(f"  ·  trigger={f.trigger}", style="dim")

        table.add_row(
            str(i),
            Text(f.severity.value.upper(), style=SEVERITY_STYLE[sev]),
            f"{f.cvss['score']:.1f}",
            Text(f.verified_label, style=VERIFIED_STYLE.get(f.verified_label, "")),
            f.vulnerability_type,
            f.parameter,
            endpoint,
        )
    console.print(table)

    # Detail blocks (payload + evidence + remediation) — what an operator needs
    console.print()
    for i, f in enumerate(ordered, 1):
        console.print(_detail_panel(i, f, verbose))

    if not any(f.browser_confirmed for f in ordered):
        console.print(
            "[yellow]None confirmed in a browser. Treat REFLECTED entries as "
            "leads: static HTML evidence is strong, but only a dialog carrying "
            "the marker proves execution.[/yellow]"
        )
        if not any(f.method.upper() == "GET" for f in ordered):
            console.print(
                "[dim]Non-GET findings cannot be replayed by navigation — POST "
                "payloads are recorded without browser proof.[/dim]"
            )


def _detail_panel(idx: int, f: XSSFinding, verbose: bool) -> "Panel":
    cvss = f.cvss
    title = Text()
    title.append(f"[{idx}] ", style="bold")
    title.append(f"{f.severity.value.upper()} ", style=SEVERITY_STYLE[f.severity])
    title.append(f"cvss {cvss['score']:.1f}  ")
    title.append(f.vulnerability_type, style="bold")
    title.append(f"  ({f.verified_label})", style=VERIFIED_STYLE.get(f.verified_label, ""))

    body = Text()
    body.append("URL      ", style="dim")
    body.append(f"{f.url}\n", style="cyan")
    body.append("Payload  ", style="dim")
    body.append(f"{f.payload}\n", style="bold")
    if f.marker:
        body.append("Marker   ", style="dim")
        body.append(f"{f.marker}\n", style="green")
    if f.trigger:
        body.append("Trigger  ", style="dim")
        body.append(f"{f.trigger}\n")
    body.append("Evidence ", style="dim")
    body.append(f"{(f.evidence or '')[:300]}\n")
    body.append("CVSS     ", style="dim")
    body.append(f"{cvss['vector']}\n", style="dim")
    body.append("Repro    ", style="dim")
    body.append(f"{reproduce_command(f)}\n", style="cyan")
    if f.filters_bypassed:
        body.append("Bypassed ", style="dim")
        body.append(", ".join(x.label for x in f.filters_bypassed) + "\n", style="yellow")
    if verbose and f.notes:
        body.append("Notes    ", style="dim")
        body.append("; ".join(f.notes) + "\n", style="dim")
    body.append("Fix      ", style="dim")
    body.append(_remediation(f), style="green")

    return Panel(body, title=title, border_style=SEVERITY_STYLE[f.severity], expand=True)


def _remediation(f: XSSFinding) -> str:
    vtype = f.vulnerability_type
    ctx = f.context.value
    if vtype in ("stored", "stored_client", "stored_or_post"):
        return (
            "Context-aware output encoding on render; sanitize stored content "
            "with a vetted HTML sanitizer (DOMPurify server-side equivalent); "
            "CSP with nonces as defence in depth."
        )
    if vtype == "dom":
        return (
            "Avoid source-to-sink assignment: use textContent or a sanitizer "
            "before innerHTML; validate the fragment against an allowlist."
        )
    if vtype == "header_reflected":
        return "Never echo request headers into HTML; encode all output."
    if vtype in ("json_body", "graphql"):
        return (
            "Encode values at the rendering layer, not the API layer; serve "
            "JSON with application/json and charset."
        )
    if vtype == "file_upload_xss":
        return (
            "Serve uploads from a separate origin with Content-Disposition: attachment, "
            "and reject SVG/HTML content types."
        )
    if vtype == "open_redirect_xss":
        return "Allowlist redirect targets; never pass user input to location.href."
    if ctx.startswith("js"):
        return (
            "Encode for the JS context (JSON-encode then escape </script>); "
            "avoid inline script with user data."
        )
    if ctx.startswith("html_attr"):
        return (
            "HTML-attribute-encode all dynamic attribute values and always quote them."
        )
    return (
        "Context-aware output encoding (HTML entity encode for text nodes), "
        "plus a strict CSP with nonces."
    )


def render_diagnoses(result: ScanResult, console: "Console") -> None:
    if not result.diagnoses:
        return
    # The title describes the *diagnoses*, not the scan: a scan can hold
    # findings and still have blocked parameters, so it never claims that
    # nothing executed when something did.
    table = Table(
        title="Diagnostics" if result.findings else "Why nothing executed here",
        title_style="bold",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Reason", width=16)
    table.add_column("HTTP", width=5, justify="center")
    table.add_column("Signal", ratio=4)
    table.add_column("Suggestion", ratio=2)

    for d in result.diagnoses[:40]:
        reason_style = {
            "waf_page": "red",
            "rate_limited": "yellow",
            "challenge": "yellow",
            "network_error": "red",
            "no_reflection": "dim",
            "filtered_payload": "yellow",
            "char_encoded": "magenta",
            "char_stripped": "magenta",
        }.get(d.reason.value, "")
        signal = Text((d.detail or "")[:220])
        if d.signals:
            signal.append("\n" + ", ".join(d.signals[:6]), style="dim")
        table.add_row(
            Text(d.reason.value, style=reason_style),
            str(d.status or ""),
            signal,
            d.suggestion or "",
        )
    console.print(table)


def render_plain(result: ScanResult) -> None:
    """Fallback renderer: clean, greppable, no rich."""
    print(f"\n=== Scan summary: {result.target_url} ===")
    print(
        f"findings={len(result.findings)} confirmed={len(result.confirmed)} "
        f"targets={result.targets_tested} requests={result.stats.requests} "
        f"duration={result.stats.duration:.1f}s"
    )
    for i, f in enumerate(result.findings, 1):
        print(
            f"\n[{i}] {f.severity.value.upper()} cvss={f.cvss['score']:.1f} "
            f"{f.vulnerability_type} ({f.verified_label})"
        )
        print(f"    url:     {f.url}")
        print(f"    param:   {f.parameter} ({f.method})")
        print(f"    context: {f.context.value}")
        print(f"    payload: {f.payload}")
        if f.marker:
            print(f"    marker:  {f.marker}")
        if f.trigger:
            print(f"    trigger: {f.trigger}")
        print(f"    evidence:{f.evidence[:200]}")
        print(f"    repro:   {reproduce_command(f)}")
    if not result.findings:
        for d in result.diagnoses[:12]:
            print(f"  - [{d.reason.value}] status={d.status} {(d.detail or '')[:140]}")
    for e in result.errors:
        print(f"error: {e}")


# ----------------------------------------------------------------------
# runner
# ----------------------------------------------------------------------


async def _run_one(url: str, cfg: Config, quiet: bool) -> tuple[ScanResult, int]:
    scanner = Scanner(cfg)
    # ``quiet`` means the caller owns stdout (``--json``): nothing from the
    # scanner may reach it, or the document stops being valid JSON.
    scanner._mute = quiet
    result = await scanner.scan(url)

    if not cfg.silent and not quiet:
        if HAS_RICH:
            console = _console()
            console.print()
            render_summary(result, console)
            render_findings(result, console, verbose=cfg.verbose)
            render_diagnoses(result, console)
        else:
            render_plain(result)

        if cfg.output:
            Path(cfg.output).parent.mkdir(parents=True, exist_ok=True)
            Path(cfg.output).write_text(result_to_json(result), encoding="utf-8")
            _say(f"JSON report  -> {cfg.output}", quiet)
        if cfg.html_report:
            path = write_html_report(result, cfg.html_report, version=__version__)
            _say(f"HTML report  -> {path}", quiet)
    else:
        if cfg.output:
            Path(cfg.output).parent.mkdir(parents=True, exist_ok=True)
            Path(cfg.output).write_text(result_to_json(result), encoding="utf-8")
        if cfg.html_report:
            write_html_report(result, cfg.html_report, version=__version__)

    rc = 0
    if result.findings:
        rc = 1  # findings found — useful exit code for CI
    elif result.errors and result.targets_tested == 0:
        rc = 2  # could not scan
    return result, rc


def _say(msg: str, quiet: bool) -> None:
    if not quiet:
        print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")


async def async_main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    urls: List[str] = []
    if args.url:
        urls.append(args.url)
    if args.list:
        path = Path(args.list)
        if not path.is_file():
            print(f"{Fore.RED}URL list not found: {args.list}{Style.RESET_ALL}")
            return 1
        urls.extend(
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    if not urls:
        parser.print_help()
        return 1

    custom_headers = {}
    for h in args.header or []:
        custom_headers.update(parse_header_string(h))

    auth = AuthConfig(
        cookie=args.cookie or "",
        bearer=args.bearer or "",
        basic=args.basic or "",
        headers=custom_headers,
        login_url=args.login_url or "",
        username=args.username or "",
        password=args.password or "",
        username_field=args.username_field,
        password_field=args.password_field,
    )

    cfg = Config(
        rate_limit=args.rate,
        workers=args.workers,
        aggressive=args.aggressive,
        guess_params=args.guess_params,
        verbose=args.verbose,
        # ``--json`` means "machine-readable stdout and nothing else": the
        # scanner's own progress log writes to stdout too, so it has to be
        # silenced here, not only at render time.
        silent=args.silent or args.json,
        timeout=args.timeout,
        max_payloads_per_param=args.max_payloads,
        output=args.output,
        html_report=args.html,
        use_browser=args.use_browser,
        deep=args.deep,
        writes=getattr(args, "writes", False),
        auth=auth,
        retries=args.retries,
        adaptive_throttle=args.adaptive,
        max_confirm_per_host=args.max_confirm,
    )

    if args.json:
        results = []
        code = 0
        for url in urls:
            result, rc = await _run_one(url, cfg, quiet=True)
            results.append(result.to_dict())
            code = max(code, rc)
        import json

        print(json.dumps(results[0] if len(results) == 1 else results, indent=2))
        return code

    code = 0
    for url in urls:
        _, rc = await _run_one(url, cfg, quiet=False)
        if rc:
            code = max(code, rc)
    return code


def main(argv: Optional[List[str]] = None) -> None:
    # Keep machine-readable output clean when piped.
    if os.environ.get("NO_COLOR"):
        try:
            from colorama import deinit

            deinit()
        except Exception:
            pass
    try:
        raise SystemExit(asyncio.run(async_main(argv)))
    except KeyboardInterrupt:
        print("Interrupted")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
