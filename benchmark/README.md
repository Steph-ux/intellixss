# Benchmark

Two targets, chosen because they fail in different ways: the PortSwigger Web
Security Academy labs, where the vulnerability is the whole page, and OWASP
Juice Shop, where it is one call inside a 1.3 MB bundle.

## PortSwigger Web Security Academy

This directory holds the evidence for the scanner's accuracy claim. Every lab
listed here is a public PortSwigger lab with a known, intended exploit; a
correct scanner finds it, and finding it does not count unless the report
shows how.

### Method

Each lab is launched through its official launch endpoint, which yields a live
instance. The instance is scanned with the stock configuration:

```python
Config(guess_params=True)
Config.auth = AuthConfig(username="wiener", password="peter")
```

`wiener:peter` is the public account every PortSwigger lab hands out, not a
credential of ours; it is used only for labs whose sink sits behind a login.

Nothing is tuned per lab. A lab that needs a special flag or a hand-written
payload is a scanner defect, and it is recorded as such rather than worked
around.

### How a result is graded

| Verdict | Meaning |
|---------|---------|
| `CONFIRMED` | A headless browser ran the payload and the payload's own `ixm…` marker came back off-origin. This is proof, not inference. |
| `static-only` | Source analysis proved a source reaches a sink, but execution was not replayed (a compile-only Angular document, a CSP that forbids alert). |
| `reflection` | Live markup reached the response; execution not observed. A lead, not a result. |
| `CLEAN` | Nothing placed. Any `CLEAN` row on a lab that is vulnerable is a false negative and is investigated. |

The distinction is the point. A scanner that reports everything as
"vulnerable" scores 100% on recall and is useless; the grade above is only
credited when a browser observed execution.

### Files

| File | Content |
|------|---------|
| `bench/benchmark.py` | The harness: launches each lab, scans it, accumulates results |
| `bench/proof.py` | Renders everything below from the accumulated JSON |
| `bench/table.py` | Console table of the current run |
| `bench/readme_table.py` | Writes the per-lab table into README.md |
| `bench/screenshots.py` | Captures README screenshots from a real scan |
| `results.json` | Machine-readable result, one object per lab |
| `SUMMARY.md` | The table, the totals, and a note on every non-confirmed lab |
| `labs/lab-NN.md` | One page per lab: payload, parameter, context, page it fired on |

Regenerate after a run:

```bash
python bench/benchmark.py       # all 30 labs, ~75 min at 4 req/s
python bench/proof.py           # rebuild the evidence in benchmark/
python bench/readme_table.py    # refresh the table in README.md
python bench/screenshots.py     # refresh docs/console.png and docs/report.png
```

Instance hosts appear in the pages because that is what the scanner saw. A lab
instance expires within the hour, so those hosts no longer answer - the path
and the lab id are what make a run traceable.

## OWASP Juice Shop

A lab is shaped like the vulnerability it teaches. Juice Shop is a full Angular
application with a REST API behind it: the document carries no form, the markup
names no endpoint, and the bundle is the only description of what the app
writes. It is the second platform because it breaks the assumptions a lab bench
can hide.

### Method

The application is started locally — Juice Shop 20.3.0, standalone release,
`node build/app.js` — and the scanner is pointed at the page, never at an
endpoint: `http://127.0.0.1:3000/`. Discovery reads the bundle, resolves the
write targets, and the stored pass drives the forms the page renders. A session
is opened with the public `admin@juice-sh.op` account the application ships
with, because two of the sinks are behind a login.

Nothing is tuned per surface. Each surface is a scan of the same page, graded
only on the sink it is about — the endpoint *and* the field — so a finding on
one API, or on another field of the same API, cannot be credited to it.

Three surfaces need state an anonymous page does not have. For those the harness
supplies identity and transport only, never a payload:

| Surface | What the harness supplies | Why |
|---|---|---|
| `last-login-ip` | a throwaway account, and the `True-Client-IP` header | the header is stored on the session's user and read back from the browser |
| `profile` | a throwaway account | the sink is the account's own stored username |
| `complaints`, `reviews`, `login` | the admin bearer | the forms sit behind a login |

The header value the harness sends is a plain word, not markup: the scanner has
to find that the header reaches storage and prove it executes. The throwaway
account is registered through `POST /api/Users` like any visitor's would be.
The report names, per surface, what was supplied, so a result obtained with a
session is never presented as one obtained without.

Each run writes records into the database the application reads back. The bench
is defined against seed data, so reset before measuring:

```powershell
powershell -File bench/reset-shop.ps1   # stops the server, drops the SQLite file
node build/app.js                       # rebuilds it from seed data
```

### Scoring

Juice Shop keeps its own list in `data/static/challenges.yml`. The bench counts
the entries whose category is `XSS` — nine in 20.3.0 — and not the Score Board,
which counts solving the room (buying a product, guessing a password, placing a
forged review) and is not something an XSS scanner does.

A challenge counts as reproduced when the scanner confirms, in a browser, an
executing payload on the sink that challenge is about.

### Result

| Surface | What it is | Verdict |
|---|---|---|
| `home` | the SPA shell, no sink of its own | clean |
| `search` | `localXssChallenge` — `#/search?q=` | reproduced, browser |
| `track` | `reflectedXssChallenge` — `#/track-result?id=` → `GET /rest/track-order/*` | reproduced, browser |
| `reviews` | `restfulXssChallenge` — `PUT /rest/products/*/reviews` | lead only (see below) |
| `feedback` | `persistedXssFeedbackChallenge` — `POST /api/Feedbacks` | clean |
| `complaints` | a stored XSS the challenge list does not cover | reproduced, browser |
| `last-login-ip` | `httpHeaderXssChallenge` — header → storage → `localStorage` | reproduced, browser |
| `profile` | `persistedXssUserChallenge` — stored username | reproduced, browser; challenge itself needs one exact literal |
| `login` | `POST /rest/user/login` | clean |

Five sinks were confirmed in total, four of which the documented challenge list
names. `POST /api/Complaints` is a real stored XSS that no challenge covers: the
bench counts it as a surface, not as a challenge.

The review surface is the one result that is a lead rather than a confirmation,
and the replay is why it is not overstated: the write is echoed back by the API
and stored, but the dialog that renders reviews in 20.3.0 binds the text as a
plain property, so it reaches the DOM escaped. See below.

`POST /api/Feedbacks` is reported clean because `sanitize-html` 1.4.2 with its
default allow-list strips the tags the challenge needs — the precision
counterpart to the confirmations, kept in the table above rather than dropped.

`benchmark/juiceshop-report.md` is generated from `benchmark/juiceshop.json` by
the harness, so the prose cannot drift from the run.

### Files

| File | Content |
|------|---------|
| `bench/juice.py` | The harness: surfaces, replay, challenge scoring, report |
| `bench/reset-shop.ps1` | Drops the database so the next start rebuilds seed data |
| `benchmark/juiceshop.json` | Machine-readable result, one object per surface |
| `benchmark/juiceshop-report.md` | Generated report: challenges, surfaces, findings |

Regenerate:

```bash
python bench/juice.py            # all surfaces, ~8 min with a browser
python bench/juice.py --list     # the roster and the documented challenges
python bench/juice.py --only reviews
python bench/juice.py --no-browser
```

`bench/*.py` import `intellixss`, so run them from the repository root with
`PYTHONPATH` set to it.

### What the scanner cannot reach here, and why

Two sinks are documented by Juice Shop but are not confirmed by a page scan.
Neither is a scanner defect; both are properties of what the application renders.
`restfulXssChallenge` stores a review through `PUT /rest/products/1/reviews`.
The product dialog in 20.3.0 binds `review.message` as a plain property, so the
text reaches the DOM escaped and never parses as markup. The challenge is still
solvable because the *request* is the attack: posting the review over the API
skips the dialog. A scanner that drives what the page renders — its own write
target, its own form — finds the endpoint and the reflection, and stops there.
Reaching it means posting a review the page does not post, which is a different
tool.

`usernameXssChallenge` is solved by the server recognising one exact string,
`<script>alert(\`xss\`)</script>`, in the stored username. The profile template
does run what is stored there, so the sink is confirmable with the scanner's own
payload; the challenge is not the sink, it is the value. The bench counts the
sink and says so, rather than claiming the challenge.

One property of that page is worth recording, because it decides what a
"confirmed" profile finding means. The rendered username lives in the `value`
attribute of the input the form re-posts, and the Pug template puts a backslash
in front of it. Reading the HTML back gives `\rc=x onerror=…` and suggests the
tag never formed. Read the DOM instead — the browser's attribute parser has
already resolved it — and the input holds the real markup. A `p` element that
renders the same string as *text* then shows why it does not fire there. The
bench confirms on the browser's view of the page and replays the write on the
wire, never on a regular expression over the response.

`#/privacy-security/last-login-ip` is the opposite case and is credited: the
header reaches storage verbatim, the component decodes the session token out of
`localStorage` and writes the value through `bypassSecurityTrustHtml`, and the
scanner confirms its own marker there.

`#/track-result?id=` first read as unreachable, and that reading was wrong. Three
defects kept an executing route off the report, and each one alone was enough:

1. The bundle detector paired a query object with the `navigate` call that
   consumes it by searching forward from the object's `{`, but the built bundle
   declares the object inside a wrapper further back than that window. The
   pairing fell through to a `navigate` from an earlier call, and the order
   history link read as `("", "id")`: the scanner probed `/` and never visited
   the component that renders the id.
2. The probe payload carried `alert('ixm…')`. The tracking page sends the id on
   to `GET /rest/track-order/*`, which builds a server-side expression around
   it: the quote ends that expression and the answer is a 500, so an executing
   route reported clean. The marker is the scanner's own, so it moved to a
   template literal, which the same builder accepts verbatim.
3. The confirmer required its marker in the dialog text. This page re-renders the
   value itself and the dialog shows the decoded id, never the raw payload, so a
   dialog the payload caused was discarded.

All three are fixed in the scanner, not worked around in the bench. The route
now confirms with the marker read back off the dialog, at the attributed
confidence, and the sink is replayed on the wire.

## Scope

PortSwigger lab instances are purpose-built targets published for exactly this
kind of testing. Juice Shop is an intentionally vulnerable application run on
localhost for the same purpose. No other host was scanned. The PortSwigger
harness refuses to launch anything that is not a `web-security-academy.net`
instance, and the Juice Shop harness talks only to the `--base` URL it is given.
