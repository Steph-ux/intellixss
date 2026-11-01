# Head-to-head: IntelliXSS vs Dalfox vs XSStrike

All scanners were pointed at the identical local range (`bench/range.py`): 10 vulnerable endpoints across distinct contexts and 10 clean controls that reflect safely or not at all. XSStrike is scored by its own `Efficiency` metric (a payload at 100 = working), not its recon lines, so the comparison is fair to it. Reproduce with `python bench/compare.py --with-xsstrike …` (below).

## Scorecard

| Scanner | Recall (found/total) | Confirmed by execution | False positives | Precision | Time |
|---|---|---|---|---|---|
| IntelliXSS | 10/10 (100%) | 10/10 | 0/10 | 100% | 75.2s |
| Dalfox | 10/10 (100%) | 10/10 | 7/10 | 59% | 246.2s |
| XSStrike | 10/10 (100%) | 0/10 | 0/10 | 100% | 117.4s |

*Confirmed by execution* means the payload was proven to run (IntelliXSS: the unique marker came back in a headless browser; Dalfox: a `V`/verified PoC). A plain *found* is reflection only.

## Per-endpoint

| Endpoint | Context | Vulnerable? | IntelliXSS | Dalfox | XSStrike |
|---|---|---|---|---|---|
| reflect_html | `html_text` | yes | CONFIRMED | CONFIRMED | found |
| reflect_attr | `attr_double` | yes | CONFIRMED | CONFIRMED | found |
| reflect_attr_sq | `attr_single` | yes | CONFIRMED | CONFIRMED | found |
| reflect_unquoted | `attr_unquoted` | yes | CONFIRMED | CONFIRMED | found |
| reflect_js | `js_string` | yes | CONFIRMED | CONFIRMED | found |
| reflect_filtered | `html_text_filtered` | yes | CONFIRMED | CONFIRMED | found |
| dom_query | `dom_query` | yes | CONFIRMED | CONFIRMED | found |
| hard_js_template | `js_template` | yes | CONFIRMED | CONFIRMED | found |
| trap_textarea | `rawtext_textarea` | no (control) | ok | **false +** | ok |
| trap_title | `rawtext_title` | no (control) | ok | **false +** | ok |
| trap_noscript | `noscript` | no (control) | ok | **false +** | ok |
| trap_template | `template` | no (control) | ok | CONFIRMED | ok |
| hard_tag_block | `html_text_tagblock` | yes | CONFIRMED | CONFIRMED | found |
| hard_attr_events | `attr_double_eventblock` | yes | CONFIRMED | CONFIRMED | found |
| safe_escaped | `html_text_escaped` | no (control) | ok | ok | ok |
| safe_attr_escaped | `attr_double_escaped` | no (control) | ok | ok | ok |
| safe_noreflect | `no_reflection` | no (control) | ok | ok | ok |
| trap_text_no_lt | `html_text_no_lt` | no (control) | ok | **false +** | ok |
| trap_attr_quote_only | `attr_double_quote_escaped` | no (control) | ok | **false +** | ok |
| trap_js_escaped | `js_string_escaped` | no (control) | ok | **false +** | ok |

## Discovery (root-only)

The table above gives every scanner the exact vulnerable URL. The other half of being the best is what each finds given only a site **root**. `bench/crawl_range.py` hides three reflected XSS off the index: a link-revealed GET param (`/search?q=`), a one-hop filter param (`/products?category=`), and a form two hops deep (`/feedback`). Pointed at the root:

| Scanner | Given only `/` | Deep XSS found |
|---|---|---|
| **IntelliXSS** | `-u http://host/ --crawl` | **3/3, browser-confirmed** |
| Dalfox | `url http://host/` | 0/3 (no link crawl) |
| XSStrike | `-u http://host/ --crawl` | 0/3 (form-only crawler) |

IntelliXSS's crawl follows same-origin links and scans each page's parameters and forms, so all three are reached and confirmed; a single-URL scan never leaves the root, and a form-only crawler misses the link-reachable GET params. Reproduce: `python bench/crawl_range.py &` then each command against `http://127.0.0.1:8890/`.

## Stored XSS (root-only)

Stored XSS is the class that most separates the tools. `bench/stored_range.py` is the real shape of it: a comment posted to `/comment` redirects to `/thanks` (the payload is never echoed back) and renders on a different page, `/posts`, linked from the index. Finding it from the root means correlating *write here* with *renders there*. Pointed at the root:

| Scanner | Given only `/` | Stored XSS |
|---|---|---|
| **IntelliXSS** | `-u http://host/ --write --crawl` | **detected** (write→render correlated across pages) |
| Dalfox | `url http://host/` | not found (no link crawl; stored needs an explicit `--trigger`) |
| XSStrike | `-u http://host/ --crawl` | not found (no stored workflow at all) |

XSStrike has no inject-here / verify-there mode, so it cannot find stored XSS by construction; Dalfox can, but only when told the trigger URL. IntelliXSS reaches it automatically from the root. The finding is reported at reflection confidence — browser-confirming a record that renders on another page is a tracked item in `AUDIT.md` — but it is a real vulnerability detected that both others miss. Reproduce: `python bench/stored_range.py &` then the commands above.

## Reproduce

```bash
# 1. Dalfox (Go)
GOBIN=$PWD/bin go install github.com/hahwul/dalfox/v2@latest
# 2. XSStrike (Python)
git clone --depth 1 https://github.com/s0md3v/XSStrike.git
pip install tld fuzzywuzzy
# 3. Run the three-way benchmark
python bench/compare.py --dalfox-bin ./bin/dalfox --with-xsstrike ./XSStrike --out benchmark/comparison.json
python bench/comparison_md.py benchmark/comparison.json
```
