# Audit status

The audit that drove this work had four points. This file states where each one
stands, what was measured, and what remains open. It is updated after every
measurement and never claims more than the evidence shows.

## 1. Detection: prove the site can execute what it places

**Done.** A finding is credited only when the browser observed the payload's own
`ixm…` marker come back. Static flows are reported as `static-only`, not as
confirmation.

**Measured** on the 30 PortSwigger labs, at commit `31c3e87`:

| Result | Count |
|--------|-------|
| Confirmed in a browser | 27 |
| Static-only (source→sink proved, execution not replayed) | 2 |
| Clean (false negative) | 1 |

The single false negative is `stored-html`, the easiest stored lab in the set:
the form posts `comment`, `name`, `email` and `website`, and only the targeted
field was sent, so the handler dropped every record. The fix fills the fields
the target's own markup declares (`intellixss/plugins/stored_xss.py`,
`_fill_untargeted_fields`).

**Open.** A re-measurement at the current commit is running; the 30-lab score
above describes the older tree. The two static-only labs are
`dom-jquery-href` and `angular-sandbox`; neither is credited, by design.

## 2. Budget: evidence first, guesses take the remainder

**Done.**

* A navigation costs one slot, charged where it is spent, never at the call
  site.
* A seeded flow — a source the page itself reads, whose sink is already named —
  declares its navigation before confirming
  (`BrowserConfirmer.note_seeded_pending`), so a route guess cannot take the
  slot first.
* A probe's reserve is the larger of the caller's and the flows still queued on
  that host, so one verification family cannot exhaust the browser.

**Proof.** `tests/test_seeded_slot_reserve.py`,
`tests/test_seeded_setup_order.py`.

## 3. Writes: opt-in, and cleaned up

**Done.**

* A read-only scan is the default. The refusal lives in `HttpClient.request`,
  the single point every request passes, so a new plugin cannot bypass it. A
  refused write returns `(0, "", {}, url)` — the shape of a network error — so
  no caller can mistake it for a success.
* A writing scan registers every record it creates *when it creates it*, builds
  the delete URL only from an identifier or `Location` header the target itself
  returned, and removes records in reverse creation order.
* What cannot be removed is reported: JSON `cleanup`, the console table, and the
  HTML report all list each record with its removal state and the reason.
* A read-only scan registers nothing and sends no `DELETE`.

**Proof.** `tests/test_read_only_default.py`, `tests/test_write_cleanup.py`,
`tests/test_cleanup_delete_url.py`, `tests/test_cleanup_wiring.py` (drives a real
local server through the orchestrator), `tests/test_cleanup_report.py`.

## 4. Analysis: a real parser beside the regex rules, not instead of them

**Done.**

* Tree-sitter and its JavaScript grammar are pinned as a verified pair.
* A scope resolver gives every declaration a symbol identity, so a shadowed
  `const hash` is not `location.hash`.
* Taint is propagated by symbol through destructuring, aliases, templates,
  closures, dynamic properties, promises and callbacks.
* Call-site arguments are joined to function parameters, gated on the body
  proving that a parameter reaches a sink, so a minified bundle's one-letter
  name collisions cannot taint anything by accident.
* The tree engine and the regex analyser run in parallel and their answers are
  merged. On any error or missing grammar the tree engine returns `None` and the
  regex answer is returned unchanged.

**Open.** On a real bundle (Juice Shop `main.js`, 1.2 MB) the tree engine still
yields no flow: the only `innerHTML` assignments write a parameter that no call
site supplies with a provable source. This is recorded, not papered over; the
regex analyser's answer is what the scanner uses there today.

**Proof.** `tests/test_js_scope_parity.py`, `tests/test_js_argument_propagation.py`,
`tests/test_js_engine_limits.py`, `tests/test_dom_engine_switch.py`.

## Known limits, stated rather than hidden

* The regex analyser matches tainted names by text, so unrelated code that
  mentions a tainted identifier within one sink's window can produce a
  `static-only` flow. It is never credited as confirmed.
* A page that has both a hash flow and a parameter flow into the same sink is
  reported only for the hash (`tests/test_dom_engine_switch.py`).
* A record whose create response names no identifier cannot be removed
  automatically; it is listed in the report for the operator.
* The stored pass is opened for `POST` targets only. A handler that stores on
  `PUT` and has no form on its page — `PUT /rest/products/1/reviews` on the
  Juice Shop — is measured as a reflection, so the sink it feeds is reported as
  a lead. The stored plugin itself writes the method it is given
  (`tests/test_stored_refused_field.py`); the gate is the orchestrator's call
  site.
* **Cross-page stored XSS is detected but not yet browser-confirmed.** A record
  posted to one endpoint and rendered on another (`/comment` → `/posts`) is now
  correlated through the site's same-origin links and reported
  (`tests/test_stored_cross_url.py`), but at reflection confidence: the markup
  probe that gates confirmation reads the render page after earlier stages have
  already written their own records to it, and the accumulated records defeat
  its "did my element survive" check (`_an_element_survives`), so the context is
  misread and no payload is browser-confirmed there. The finding is never
  dressed up as confirmed. The fix is to isolate the probe's own record on an
  accumulating page before judging the sink; it is open.
