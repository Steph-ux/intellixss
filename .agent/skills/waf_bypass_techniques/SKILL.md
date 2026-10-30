---
name: waf_bypass_techniques
description: How IntelliXSS v3 turns an observed filter into payload mutations - measured, not guessed
---

# Filter Evasion in IntelliXSS v3

## Principle

v3 does not "try every WAF trick". It measures what the target actually does to
the payload, then rewrites the payload so the part that survived carries the
execution.

The loop:

```
1. detect      analyse/filters.py        which filters, WAF and CSP are present
2. probe       analysis/charprobe.py     which characters survive, one request per char
3. mutate      payloads/mutations.py     rewrite the payload around what survives
4. regenerate  payloads/generator.py     re-rank families against the surviving set
5. confirm     verify/browser.py         prove it in the browser, or record why not
```

A mutation that has not survived steps 2 and 5 is a guess, and guesses are
what make scanners noisy.

## Stage 1 - Detection

`analysis/filters.py` classifies from response evidence, never from a hunch:

```python
WAF_HEADER_SIGS = [("cf-ray", FilterType.WAF_CLOUDFLARE, "cloudflare"), ...]
WAF_BODY_SIGS   = [("modsecurity", FilterType.WAF_MODSEC, "modsecurity"), ...]
```

Behaviours are classified into `FilterType` (`STRIP_TAGS`, `STRIP_EVENTS`,
`BLOCK_ANGLE`, `HTML_ENCODE`, `JS_ENCODE`, `CSP`, `CSP_STRICT`, ...). To add a
WAF, add a fingerprint tuple to the right list:

```python
("x-my-waf-trace", FilterType.WAF_GENERIC, "my-waf"),
```

Prefer a header the vendor always sets over a body string that marketing pages
can also contain.

## Stage 2 - Character survival

`analysis/charprobe.py` sends each character of interest and reads back what
the response echoed. The result (`CharProbeResult`) separates:

- `allowed_chars` - survived verbatim, usable;
- `encoded_chars` - came back as an entity or escape, therefore *unusable* as
  syntax (it renders as text);
- `stripped_chars` - removed.

Payload families are then ranked by whether their technique needs a character
the target destroys. That is why a payload using `"` is dropped for a quote
that is encoded, while a backtick or `onmouseover` family is offered instead.

## Stage 3 - Mutations

`payloads/mutations.py` - pure string transforms, no network:

| Function | What it changes |
|----------|-----------------|
| `case_variation` | tag/attribute case, skipping JS identifiers that must stay lowercase |
| `tab_bypass` / `whitespace_bypass` | separator replacement |
| `slash_bypass` | `<svg/onload>` form |
| `comment_injection` | `<!-- -->` inside a tag |
| `html_entity_event` | entity-encoded event name |
| `backtick_call` | `alert(\`marker\`)` for quoted-attribute contexts |
| `null_byte_soft` | soft null between tokens (WAF profiles only) |
| `mixed_case_tags` | mixed-case tags (WAF profiles only) |
| `filter_by_char_survival` | keep only variants made of surviving characters |

`apply_mutations(payload, filters)` returns the whole family for one payload;
`mutate_for_waf` expands and truncates a list.

## Stage 4 - WAF profiles

`payloads/waf_profiles.py` maps the detected filter to a named profile
(`sucuri`, `cloudflare`, `modsec`, `f5`, `fortiweb`, `barracuda`, `azure`,
`generic_waf`) and returns that profile's hand-tuned payloads via
`get_waf_payloads(filters)`. Add a profile by:

```python
MYWAF_PAYLOADS = [
    "<img src=x onerror=PO>",
    ...
]
_BY_PROFILE["my-waf"] = MYWAF_PAYLOADS
```

then map the filter in `profile_for_filters`.

## Stage 5 - Server-side rewrites

`intellixss/encode.py` covers the transforms the *application* applies, which
are not WAF bypasses but still defeat a naive payload:

- percent and double-percent encoding,
- HTML entity (decimal and hex),
- unicode escapes (`\u003c`) for JSON and JS string contexts,
- backslash escaping direction - measured, never assumed. A delimiter behind a
  backslash is treated as `escaped`, not `blocked`, because the server can
  decode before use.

An allowlist that survives a tag but strips every handler is handled by
learning the allowlist (`scanner/orchestrator.py::_escalate_allowlist`,
`_allowlist_payloads`, `_escalate_animated_attr`): the surviving tag is
re-used and an attribute the filter does not name is attached, for example
`<svg><a><animate attributeName=href values=javascript:...>`.

## Decision matrix

| Observed | First technique |
|----------|-----------------|
| nothing filtered | shortest direct tag |
| angle brackets blocked | attribute breakout from a surviving context |
| tags stripped | event on an allowed tag, then SVG/MathML |
| events stripped | `javascript:` in an allowed URL attribute |
| `javascript:` blocked | SVG `<animate>` / `<set>` spelling variants, then `data:` |
| quotes encoded | backtick or unquoted forms only |
| double-encoded | raise `encoding_level` in the generator |
| strict CSP | no inline script: form hijack, redirect, or a self-hosted script |

## Testing a bypass

```python
from intellixss.models import FilterType
from intellixss.payloads.mutations import apply_mutations, filter_by_char_survival

base = "<img src=x onerror=alert('ixm1a2b3c4d')>"
variants = apply_mutations(base, [FilterType.WAF_CLOUDFLARE])
assert variants[0] == base

kept = filter_by_char_survival(variants, blocked={"<"}, encoded={'"'})
assert kept and all(v.strip() for v in kept)
```

`filter_by_char_survival(payloads, blocked, encoded, min_keep=5)` drops the
variants whose syntax depends on a destroyed character and keeps encoded or
`fromCharCode` forms, which survive a raw-character filter by construction.

Then a live run:

```bash
python intellixss.py -u https://your-lab/ -v
```

The verbose trace must show the probe result and the family chosen from it.

## Do not

- Do not add a mutation that drops or mangles the `ixm...` marker - it makes
  the payload unconfirmable.
- Do not call `case_variation` on JS identifiers; `_PRESERVE_TOKENS` exists
  because `ALERT()` is not `alert()`.
- Do not treat an encoded character as usable syntax.
- Do not add a payload family without a survival rule in `charprobe` /
  `_rank`; unranked families burn the request budget.
