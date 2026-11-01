# Head-to-head: IntelliXSS vs Dalfox vs XSStrike

All scanners were pointed at the identical local range (`bench/range.py`): seven vulnerable endpoints across distinct contexts and three clean controls that reflect safely or not at all. Reproduce with `python bench/compare.py` (see below).

## Scorecard

| Scanner | Recall (found/total) | Confirmed by execution | False positives | Precision | Time |
|---|---|---|---|---|---|
| IntelliXSS | 9/9 (100%) | 8/9 | 0/6 | 100% | 62.0s |
| Dalfox | 9/9 (100%) | 9/9 | 3/6 | 75% | 178.1s |

*Confirmed by execution* means the payload was proven to run (IntelliXSS: the unique marker came back in a headless browser; Dalfox: a `V`/verified PoC). A plain *found* is reflection only.

## Per-endpoint

| Endpoint | Context | Vulnerable? | IntelliXSS | Dalfox |
|---|---|---|---|---|
| reflect_html | `html_text` | yes | CONFIRMED | CONFIRMED |
| reflect_attr | `attr_double` | yes | CONFIRMED | CONFIRMED |
| reflect_attr_sq | `attr_single` | yes | CONFIRMED | CONFIRMED |
| reflect_unquoted | `attr_unquoted` | yes | CONFIRMED | CONFIRMED |
| reflect_js | `js_string` | yes | CONFIRMED | CONFIRMED |
| reflect_filtered | `html_text_filtered` | yes | CONFIRMED | CONFIRMED |
| dom_query | `dom_query` | yes | CONFIRMED | CONFIRMED |
| hard_tag_block | `html_text_tagblock` | yes | found | CONFIRMED |
| hard_attr_events | `attr_double_eventblock` | yes | CONFIRMED | CONFIRMED |
| safe_escaped | `html_text_escaped` | no (control) | ok | ok |
| safe_attr_escaped | `attr_double_escaped` | no (control) | ok | ok |
| safe_noreflect | `no_reflection` | no (control) | ok | ok |
| trap_text_no_lt | `html_text_no_lt` | no (control) | ok | **false +** |
| trap_attr_quote_only | `attr_double_quote_escaped` | no (control) | ok | **false +** |
| trap_js_escaped | `js_string_escaped` | no (control) | ok | **false +** |

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
