---
name: add_scanner_module
description: How to add a specialized XSS plugin to IntelliXSS v3 (intellixss/plugins)
---

# Adding a Scanner Plugin to IntelliXSS v3

## Context

v3 has no monolithic orchestrator class. A "scanner module" is a **plugin**:
a module under `intellixss/plugins/` exposing a single `scan_*` coroutine that
the orchestrator (`intellixss/scanner/orchestrator.py`) calls when the target
shape matches. Plugins never talk to Playwright directly; they receive the
shared `HttpClient`, `BrowserConfirmer` and `ScanConfig`.

Existing plugins:

| Module | Entry point | Triggered by |
|--------|-------------|--------------|
| `stored_xss.py` | `scan_stored(client, config, browser)` | always (bounded) |
| `header_xss.py` | `scan_headers(client, config)` | `--deep` |
| `redirect_xss.py` | `scan_redirects(client, config)` | `--deep` |
| `json_xss.py` | `scan_json_endpoints(client, config)` | `--deep`, JSON-shaped targets |
| `graphql_xss.py` | `scan_graphql(client, config)` | `--deep`, GraphQL endpoint discovered |
| `upload_xss.py` | `scan_uploads(client, config)` | `--deep`, forms with `enctype=multipart` |

## Step 1 - Define the evidence contract first

A plugin does not decide whether something is exploitable. It produces
`Finding` objects carrying `verified_by`:

```
"browser"    the payload executed in headless Chromium (marker echoed)
"reflection" live markup reached the response, execution not observed
"static"     source-to-sink / compiler analysis only
```

Pick the strongest state the plugin can honestly reach. If a plugin can only
see a reflection, it must set `verified_by="reflection"` - never `"browser"`.

## Step 2 - Write the plugin

```python
"""Header-borne XSS plugin."""

from __future__ import annotations

from dataclasses import replace

from intellixss.models import Finding


async def scan_my_vector(client, config) -> list[Finding]:
    findings: list[Finding] = []

    await config.report.note("my-vector", f"probing {config.target}")

    response = await client.get(config.target)
    if response is None:
        return findings

    payload, marker = config.payloads.build(context="html_text")
    echoed = payload in response.text

    if echoed:
        findings.append(
            replace(
                config.base_finding(),
                parameter="X-My-Vector",
                method="GET",
                context="html_text",
                payload=payload,
                payload_marker=marker,
                verified_by="reflection",
                evidence="payload echoed verbatim in response body",
            )
        )
    return findings
```

Rules the plugin must respect:

- **One request per probe**, through the shared client, so the rate limiter and
  adaptive throttling apply.
- **Bounded work.** Every plugin gets a phase deadline from the orchestrator.
  Check it between probes; never spin.
- **No browser alert checks.** To escalate a reflection to `"browser"`, hand
  the render URL to `browser.confirm(...)`; the confirmer owns dialogs,
  markers and deadlines.
- **No hardcoded payload literals.** Ask `config.payloads.build(context=...)`
  so the generator, encoders and WAF profiles stay in charge.

## Step 3 - Register the plugin

In `intellixss/scanner/orchestrator.py`, inside `Scanner.scan()`, next to the
other plugin calls:

```python
if config.deep:
    findings.extend(await scan_my_vector(self._client, config))
```

Add a CLI gate only if the plugin is genuinely expensive; prefer reusing
`--deep`.

## Step 4 - Tests

Add `tests/test_my_vector.py`. Use a fake client (see
`tests/test_stored_render_and_fragment.py` for the pattern) and assert:

1. happy path -> one finding, correct `verified_by`;
2. no reflection -> zero findings;
3. client failure -> zero findings, no exception.

```bash
python -m pytest -q tests/test_my_vector.py
```

## Step 5 - Validate against a real target

```bash
python intellixss.py -u https://your-lab/ --deep -v --no-browser
python intellixss.py -u https://your-lab/ --deep -v   # browser confirmation
```

The first run must show the reflection; the second should move the finding to
`verified_by="browser"` with a confidence of `0.97`.

## Do not

- Do not import Playwright inside a plugin.
- Do not add a second HTTP session; reuse `HttpClient`.
- Do not raise on network errors - return the findings collected so far.
- Do not carry v2 names (`IntelliXSS`, `InjectionContext`, `XSSFinding`,
  `BrowserValidator`); they no longer exist.
