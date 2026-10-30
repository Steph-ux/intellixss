---
name: playwright_browser_validation
description: How IntelliXSS v3 proves execution in a browser - marker-causal confirmation, off-origin evidence, deadlines
---

# Browser Validation in IntelliXSS v3

## Principle

A reflection is not an execution. The browser confirmer answers one question:
*did the payload we sent actually run?* It answers it causally, not
heuristically - every payload carries a unique marker
(`ixm<8 hex>`, from `payloads.generator.make_marker`), and execution is only
credited when that marker comes back from a request the page made.

There is no `BrowserValidator` class and no global dialog flag. A page that
raises `alert(1)` on its own is not evidence, and v3 does not count it.

## API

All of this lives in `intellixss/verify/browser.py::BrowserConfirmer`.

```python
result = await browser.confirm(
    url,                       # the URL to load
    payload="<svg onload=alert('ixm1a2b3c4d')>",
    marker="ixm1a2b3c4d",
    context_hint="html_text",
    referrer="",               # seeds document.referrer sinks
    window_name="",            # seeds window.name sinks
    cookies=[("k", "v")],      # seeds cookie-driven sinks
    warm_url="",               # open this document first (stored payloads)
)
if result.confirmed:
    ...                        # result.detail explains how it was proven
```

`confirm_markup(markup, marker=...)` is the sibling entry point for a document
the scanner builds itself (stored render pages, response bodies captured
before the browser existed).

`confirm_client_stored(...)` drives form -> render flows where the payload is
written by the page's own JavaScript.

Optional arguments that matter:

| Argument | Why |
|----------|-----|
| `referrer` | `document.referrer` has no URL parameter; it must be seeded |
| `window_name` | same for `window.name` |
| `cookies` | same for cookie reads |
| `warm_url` | the record page, when the write endpoint returns nothing |
| `exec_code` | an expression the confirmer may evaluate, when allowed |

## What counts as proof

```
marker echoed back by an OFF-ORIGIN, non-document request  -> confirmed, 0.97
dialog fired, no marker                                    -> kept, 0.85
nothing                                                    -> not confirmed
```

An on-origin image request does not prove execution - the page could embed
the marker as text. The confirmer installs a console hook and a request
listener (`_CONSOLE_HOOK`) and only credits a marker that travels off-origin,
or that appears in `console.log`, which only running code can call.

## Deadlines

Every confirmation is wrapped in a wall-clock budget
(`browser_timeout_ms / 1000 + settle + close`). On exhaustion it returns
`BrowserConfirmResult(False, "confirm_timeout")` - never raises, never hangs.
Callers must treat `confirm_timeout` as *unknown*, not as *clean*.

Do not call `page.goto` yourself from a plugin. Route everything through
`confirm` / `confirm_markup` so the deadline and the navigation budget
(`--max-confirm`) always apply.

## Event firing

Handlers that need activation are exercised by `fire_handler(page, handler,
marker)`, which returns a dict describing which trigger fired
(`load`, `hashchange`, `click`, `focus`, `hover`, `interaction`, `eval`).
`_try_js_href_clicks` handles `javascript:` links, including links inside
`<svg><a>` animated by `<animate attributeName=href>` - a plain
`query_selector('a')` misses those.

## Pitfalls

| Symptom | Cause |
|---------|-------|
| `confirm_budget_exhausted` | `--max-confirm` reached; raise it or split the target |
| Dialog seen but not confirmed | payload did not carry the marker, or the page raised it |
| Stored payload never fires | the record page was not opened first - pass `warm_url` |
| Always `browser_unavailable` | `playwright install chromium` was not run |
| Click hits the wrong element | click the element that carries *our* marker, not the first match |

## Configuration

```python
config.browser_timeout_ms   # per-navigation timeout
config.max_confirm          # navigations per host (default 12)
```

`--no-browser` disables confirmation entirely; findings then stop at
`verified_by="reflection"`.
