# Benchmark — PortSwigger Web Security Academy, XSS

This directory holds the evidence for the scanner's accuracy claim. Every lab
listed here is a public PortSwigger lab with a known, intended exploit; a
correct scanner finds it, and finding it does not count unless the report
shows how.

## Method

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

## How a result is graded

| Verdict | Meaning |
|---------|---------|
| `CONFIRMED` | A headless browser ran the payload and the payload's own `ixm…` marker came back off-origin. This is proof, not inference. |
| `static-only` | Source analysis proved a source reaches a sink, but execution was not replayed (a compile-only Angular document, a CSP that forbids alert). |
| `reflection` | Live markup reached the response; execution not observed. A lead, not a result. |
| `CLEAN` | Nothing placed. Any `CLEAN` row on a lab that is vulnerable is a false negative and is investigated. |

The distinction is the point. A scanner that reports everything as
"vulnerable" scores 100% on recall and is useless; the grade above is only
credited when a browser observed execution.

## Files

| File | Content |
|------|---------|
| `_psbench.py` | The harness: launches each lab, scans it, accumulates results |
| `_psproof.py` | Renders everything below from the accumulated JSON |
| `_pstable.py` | Console table of the current run |
| `results.json` | Machine-readable result, one object per lab |
| `SUMMARY.md` | The table, the totals, and a note on every non-confirmed lab |
| `labs/lab-NN.md` | One page per lab: payload, parameter, context, page it fired on |

Regenerate after a run:

```bash
python _psbench.py          # all 30 labs, ~75 min at 4 req/s
python _psproof.py          # rebuild the evidence in benchmark/
```

Instance hosts appear in the pages because that is what the scanner saw. A lab
instance expires within the hour, so those hosts no longer answer - the path
and the lab id are what make a run traceable.

## Scope

PortSwigger lab instances are purpose-built targets published for exactly
this kind of testing. No other host was scanned. The harness refuses to launch
anything that is not a `web-security-academy.net` instance.
