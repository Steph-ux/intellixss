---
name: add_xss_payload_category
description: How to add a payload family or a new injection context to the IntelliXSS v3 generator
---

# Adding a Payload Category to IntelliXSS v3

## Context

Payloads live in `intellixss/payloads/generator.py`. There is no
`PayloadGenerator` class any more - the engine is a function plus template
banks:

```
_BANK: dict[InjectionContext, list[str]]      one bank per context
_UNIVERSAL                                    always-viable fallback
generate_payloads(context, filters, char_probe, marker, quote_char, ...)
```

Placeholders inside a template:

| Token | Replaced with |
|-------|---------------|
| `PO` | the full binder `alert('ixm...')` |
| `A` | the same call written for a *quoted* attribute (backticks) |
| `Q` | the attribute delimiter the analyser actually saw (`"` or `'`) |

Every payload must carry the per-scan marker. A payload that cannot report a
marker can never be browser-confirmed - it only ever reaches `"reflection"`.

## Step 1 - Decide what you are adding

| Situation | Where it goes |
|-----------|---------------|
| New trick inside an existing context | extend that context's list in `_BANK` |
| New injection context | new `InjectionContext` member + analyser branch + bank |
| Server-side rewrite (allowlist, entity, double URL) | a transform in `encode.py` or `mutations.py`, not a new bank |

Do not add a bank entry for something a filter already covers by mutation.

## Step 2 - Add the templates

```python
_HTML_TEXT = [
    # ... existing ...
    "<details open ontoggle=PO>",
]
```

Rules:

- **Five to twenty templates per family.** More than that costs requests and
  produces near-duplicates.
- **One technique per template.** A payload that tries three tricks at once
  cannot tell you which one survived.
- **Structural, not textual.** `alert(1)` as bare text is noise; the generator
  drops such entries (`_is_alert_noise`).
- **Comment the mechanism**, not the source. Say what the browser does with it.

## Step 3 - New injection context (if needed)

1. Add the member in `intellixss/models.py`:

   ```python
   class InjectionContext(str, Enum):
       ...
       MY_CONTEXT = "my_context"
   ```

2. Teach the analyser. `intellixss/analysis/context.py::detect_context` is a
   small HTML5 state machine over the parsed response. A new context is a new
   state transition, not a regex over the whole document:

   ```python
   if state is State.IN_ATTRIBUTE and attr_name == "my_attr":
       return InjectionContext.MY_CONTEXT
   ```

3. Register the bank: `_BANK[InjectionContext.MY_CONTEXT] = _MY_CONTEXT`.

4. Add a test in `tests/test_context.py` that injects a marker into a real
   fragment and asserts the returned context. The context must be derived from
   where the marker actually landed, never from the field name.

## Step 4 - Ordering

`generate_payloads` already orders by `_rank`, which prefers payloads whose
technique is viable against the measured character survival. If you add a
family, check that `_rank` can tell it apart - if two families are
indistinguishable to the ranker, merge them.

## Step 5 - Validate

```python
from intellixss.models import InjectionContext
from intellixss.payloads.generator import generate_payloads, make_marker

m = make_marker("deadbeef")
out = generate_payloads(InjectionContext.MY_CONTEXT, marker=m)
assert out, "empty bank"
assert all(m in p or "<" in p for p in out)
print(len(out), out[0])
```

Then against a live lab:

```bash
python intellixss.py -u https://your-lab/ -v
```

The verbose trace must show the new family attempted, its survival, and either
a marker echo or the reason it was dropped.

## Do not

- Do not hardcode marker values; always use `make_marker`.
- Do not add `alert(1)`-only payloads for browser-driven contexts - the
  confirmer requires the marker to attribute execution.
- Do not put a payload in `_UNIVERSAL` unless it is safe in *every* context;
  universal entries are tried after the specific bank and can produce false
  leads.
