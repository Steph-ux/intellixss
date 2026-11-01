# Head-to-head: IntelliXSS vs Dalfox vs XSStrike

All scanners were pointed at the identical local range (`bench/range.py`): seven vulnerable endpoints across distinct contexts and three clean controls that reflect safely or not at all. Reproduce with `python bench/compare.py` (see below).

## Scorecard

| Scanner | Recall (found/total) | Confirmed by execution | False positives | Precision | Time |
|---|---|---|---|---|---|
| IntelliXSS | 7/7 (100%) | 7/7 | 0/3 | 100% | 38.3s |
| Dalfox | 7/7 (100%) | 7/7 | 0/3 | 100% | 121.1s |

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
| safe_escaped | `html_text_escaped` | no (control) | ok | ok |
| safe_attr_escaped | `attr_double_escaped` | no (control) | ok | ok |
| safe_noreflect | `no_reflection` | no (control) | ok | ok |

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
