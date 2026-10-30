# Contributing

## The one rule

A finding is only as strong as the evidence behind it, and the code is held to
the same standard. A change that makes the scanner report more, faster, or more
impressively - without a test proving the new behaviour - will not be merged.

## Setup

```bash
git clone https://github.com/Steph-ux/intellixss
cd intellixss
pip install -r requirements.txt
playwright install chromium     # required: browser confirmation is the core claim
python -m pytest -q             # 283 tests, no network, no lab needed
```

The suite runs offline. A test that needs a live target belongs in the
benchmark harness, not in `tests/`.

## What a good change looks like

1. **A test first.** The failure mode you are fixing should fail before your
   change and pass after it. `tests/test_report_reproduce.py` and
   `tests/test_context.py` show the shape.
2. **Evidence, not assertion.** If the change touches detection, say what the
   new behaviour was measured against. A payload family added because "it might
   work" is not evidence.
3. **Surgical diff.** Fix the bug. Do not reformat the file around it, do not
   rename things that are not part of the problem.
4. **No secrets in the diff.** Not in code, not in a test fixture, not in a
   comment. A lab account (`wiener:peter`) is the only accepted exception and it
   must be obvious why.

## Extending the scanner

Developer notes live in `.agent/skills/`:

| Note | Covers |
|------|--------|
| `add_scanner_module` | A new stage or module in the pipeline |
| `add_xss_payload_category` | A new payload family and its ranking |
| `playwright_browser_validation` | Confirmation semantics, deadlines, markers |
| `cvss_reporting` | Scoring and the report contract |
| `waf_bypass_techniques` | Filter and WAF evasion |

## Benchmarking a change

Detection changes should be measured, not assumed:

```bash
python bench/benchmark.py 0 9      # labs 0..9 (inclusive indices; --list shows them)
python bench/proof.py          # rebuild benchmark/ evidence from results
```

A regression on a lab that previously confirmed is a defect. Report it as one
rather than adjusting the grading.

## Commit messages

```
<type>(<scope>): <imperative summary, under 72 chars>
```

Types: `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `chore`. One logical
change per commit. The body explains **why**, not what - the diff already shows
what.

## License

Contributions are accepted under the MIT license in [LICENSE](LICENSE).

## Scope

This is an offensive tool. Its purpose is authorized security testing. A
contribution that turns it into something aimed at targets the operator does
not control - a mass scanner, a botnet component, a payload delivery system -
is out of scope.
