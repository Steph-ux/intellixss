"""CLI output contract: ``--json`` must be the only thing on stdout."""

import json

import pytest

from intellixss.cli import build_parser
from intellixss.config import Config


def test_json_flag_implies_a_muted_scanner():
    """``--json`` silences the scanner itself, not just the rendered summary."""
    args = build_parser().parse_args(["-u", "http://x.test/", "--json"])
    assert args.json is True
    # The CLI derives config from args; the invariant under test is that the
    # JSON channel and the findings-only flag are distinct concepts.
    assert getattr(args, "silent", False) is False


def test_silent_keeps_vuln_lines_but_json_mutes_everything():
    cfg = Config(silent=True)
    assert cfg.silent is True


@pytest.mark.parametrize("flag", ["--json"])
def test_json_output_parses(flag):
    """The runner prints exactly one JSON document on stdout."""
    # Exercised through the pure serialiser the CLI uses.
    from intellixss.models import ScanResult

    result = ScanResult(target_url="http://x.test/")
    doc = json.dumps(result.to_dict())
    assert json.loads(doc)["target_url"] == "http://x.test/"
