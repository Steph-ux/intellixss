# Quarantine

Non-scanner artifacts that were previously mixed into the repository root,
kept separate from the scanner entry path:

- `scripts/` - one-off recon, MITM, keylogger and VPS helpers
- `pcaps/` - packet captures
- `exploits_bundle/` - generated exploit HTML from earlier runs
- `exploits/` - now empty; exploit HTML is written next to each JSON report

`exploits_bundle/` and the `exploits/<timestamp>_<host>/` directories hold
material captured against PortSwigger Web Security Academy lab hosts that no
longer exist; treat them as stale and do not reuse them in a report.

None of this is imported by `python intellixss.py` or `python -m intellixss`.
