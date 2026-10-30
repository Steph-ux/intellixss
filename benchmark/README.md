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

Nothing is tuned per surface. The six surfaces are six scans of the same page;
each one is graded only on the sink it is about, so a finding on one API cannot
be credited to another.

### Scoring

Juice Shop keeps its own list in `data/static/challenges.yml`. The bench counts
the entries whose category is `XSS` — nine in 20.3.0 — and not the Score Board,
which counts solving the room (buying a product, guessing a password, placing a
forged review) and is not something an XSS scanner does.

A challenge counts as reproduced when the scanner confirms, in a browser, an
executing payload on the sink that challenge is about.

### Result

| Documented XSS challenge | Sink | Result |
|---|---|---|
| API-only XSS | `PUT /rest/products/1/reviews` | reproduced |
| DOM XSS | `GET /#/search?q=` | reproduced |
| Server-side XSS Protection | `POST /api/Feedbacks` | clean (expected) |
| six others | — | not reached by this roster |

Three real sinks were confirmed in total. The third, `POST /api/Complaints`, is
a stored XSS that no documented challenge covers. `POST /api/Feedbacks` is
reported clean because `sanitize-html` with its default allow-list stores the
payload as text — the precision counterpart to the confirmations.

`benchmark/juiceshop-report.md` is generated from `benchmark/juiceshop.json` by
the harness, so the prose cannot drift from the run.

### Files

| File | Content |
|------|---------|
| `bench/juice.py` | The harness: six surfaces, replay, challenge scoring, report |
| `benchmark/juiceshop.json` | Machine-readable result, one object per surface |
| `benchmark/juiceshop-report.md` | Generated report: challenges, surfaces, findings |

Regenerate:

```bash
python bench/juice.py            # all six surfaces, ~6 min with a browser
python bench/juice.py --list     # the roster and the documented challenges
python bench/juice.py --only reviews
python bench/juice.py --no-browser
```

`bench/*.py` import `intellixss`, so run them from the repository root with
`PYTHONPATH` set to it.

## Scope

PortSwigger lab instances are purpose-built targets published for exactly this
kind of testing. Juice Shop is an intentionally vulnerable application run on
localhost for the same purpose. No other host was scanned. The PortSwigger
harness refuses to launch anything that is not a `web-security-academy.net`
instance, and the Juice Shop harness talks only to the `--base` URL it is given.
