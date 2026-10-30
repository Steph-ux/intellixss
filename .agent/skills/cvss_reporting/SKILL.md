---
name: cvss_reporting
description: How IntelliXSS v3 scores findings (CVSS v3.1) and how the JSON / HTML reports are produced
---

# Scoring and Reporting in IntelliXSS v3

## Where it lives

| Concern | Module |
|---------|--------|
| Score table, severity mapping | `intellixss/models.py` (`_CVSS_TABLE`, `score_to_severity`, `compute_cvss`) |
| Finding shape | `intellixss/models.py` (`Finding` / `XSSFinding`) |
| Result aggregation | `intellixss/models.py` (`ScanResult.max_severity`, `counts_by_severity`) |
| HTML report | `intellixss/report/html_report.py` (`write_html_report`) |
| Console rendering and JSON | `intellixss/cli.py` |

There is no `ReportGenerator` class. Scoring is a pure function of the
finding's type and its evidence.

## The score table

`_CVSS_TABLE` is keyed by `(vulnerability_type, browser_confirmed)` and holds
`(score, vector)`. Severity comes from the score, not from the table:

```
>= 9.0  CRITICAL
>= 7.0  HIGH
>= 4.0  MEDIUM
>  0.0  LOW
```

Current families:

| Type | Confirmed | Not confirmed |
|------|-----------|---------------|
| `reflected` | 6.1 | 4.3 |
| `stored`, `stored_client` | 8.8 | 6.5 |
| `dom` | 7.4 | 5.4 |
| `header_reflected` | 6.1 | 4.3 |
| `json_body`, `graphql` | 7.2 | 5.4 |
| `graphql_stored` | 8.8 | 6.5 |
| `file_upload_xss` | 7.4 | 5.4 |
| `open_redirect_xss`, `stored_or_post` | 6.1 | 4.3 |

An unknown type falls back to the `reflected` family, which is why a new plugin
must register its type rather than rely on the default.

Lookup:

```python
from intellixss.models import compute_cvss
compute_cvss("stored", True)      # {'score': 8.8, 'severity': 'high', 'vector': '...'}
compute_cvss("dom", False)        # {'score': 5.4, 'severity': 'medium', 'vector': '...'}
```

## Adding a vulnerability type

1. Pick the closest base metric set. XSS almost always needs `UI:R`,
   `S:C` once execution is proven, and `PR:L` for types that need a writer
   account (stored, GraphQL mutations, uploads).

2. Add both rows - confirmed and not confirmed - to `_CVSS_TABLE`:

   ```python
   ("my_type", True): (7.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
   ("my_type", False): (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
   ```

3. Emit the type from the plugin:

   ```python
   finding.vulnerability_type = "my_type"
   ```

4. Add remediation text in `intellixss/report/html_report.py::_remediation`,
   keyed by type and context. Keep it a concrete fix (encoder, API, header),
   not a policy sentence.

5. Test it:

   ```python
   def test_my_type_scoring():
       assert compute_cvss("my_type", True)["score"] == 7.7
       assert compute_cvss("my_type", False)["severity"] == "medium"
   ```

## Evidence discipline

`browser_confirmed` is the single input that moves a finding from the weaker
row to the stronger one, so it must never be set optimistically. It is true
only when the confirmer saw the payload's own marker come back. The report
also exposes `verified_by` (`browser` / `reflection` / `static`) so a reader can
tell a proven execution from a live reflection.

## Reports

```bash
python intellixss.py -u https://target/ -o report.json --html report.html
python intellixss.py -u https://target/ --json > report.json
```

- `--json` prints the serialised `ScanResult` and nothing else - no banners, no
  colour - so it is safe to pipe.
- `--html` renders verdict, findings (proof, CVSS, remediation), diagnostics
  and metadata.
- `-o` writes the same JSON structure to a file.

Exit codes: `0` no findings, `1` findings, `2` the scan could not run. CI
should treat `2` as an error, not as clean.

## Do not

- Do not re-score a finding at report time differently from `models.compute_cvss`
  - the console, HTML and JSON must agree.
- Do not invent severity bands; add a row and let `score_to_severity` derive it.
- Do not include raw response bodies in the JSON: they can carry other users'
  data. Keep the marker, the payload and the evidence sentence.
