"""Blind / out-of-band payload construction and the honesty contract.

A blind payload cannot be confirmed here, so these tests pin the two things
that make it trustworthy anyway: every beacon points off-origin at the
operator's host and carries the correlation marker, and the CLI/config plumbing
that turns it on exists and is wired through.
"""

from intellixss.config import Config
from intellixss.cli import build_parser
from intellixss.payloads.blind import (
    beacon_host,
    beacon_url,
    build_blind_payloads,
    correlation_token,
    normalize_oob,
)


def test_normalize_accepts_bare_host_and_scheme_forms():
    for form in ("oast.example", "//oast.example", "https://oast.example"):
        base, host = normalize_oob(form)
        assert host == "oast.example"
        assert base == "//oast.example"
    # A path is preserved and the trailing slash trimmed.
    base, host = normalize_oob("https://oast.example/hook/")
    assert base == "//oast.example/hook"
    assert host == "oast.example"


def test_empty_oob_yields_nothing():
    assert normalize_oob("") == ("", "")
    assert beacon_url("", "ixmabc123") == ""
    assert build_blind_payloads("", "ixmabc123") == []


def test_correlation_token_normalises_marker():
    assert correlation_token("ixmabc123") == "ixmabc123"
    assert correlation_token("abc123") == "ixmabc123"
    assert correlation_token("") == "ixm"


def test_beacon_url_and_host_carry_the_marker():
    assert beacon_url("oast.example", "ixmdead01") == "//oast.example/ixmdead01"
    assert beacon_host("oast.example", "ixmdead01") == "ixmdead01.oast.example"


def test_every_payload_is_off_origin_and_marked():
    marker = "ixmdeadbeef"
    payloads = build_blind_payloads("https://oast.example", marker)
    assert payloads, "expected a non-empty blind payload set"
    for p in payloads:
        # Off-origin: each beacon names the collaborator host, never a relative
        # path that would hit the target itself.
        assert "oast.example" in p
        # Correlatable: the marker rides along so an OOB hit names this point.
        assert marker in p
    # Context coverage: a tag break-out, an inline handler, a js: URL and a bare
    # stored form are all present, so one set fits wherever the value lands.
    joined = "\n".join(payloads)
    assert "<script src=" in joined
    assert "onerror=" in joined or "onmouseover=" in joined
    assert "javascript:fetch(" in joined
    assert beacon_host("oast.example", marker) in joined  # DNS-only form


def test_cli_exposes_blind_flags_and_config_carries_them():
    args = build_parser().parse_args(
        ["-u", "http://x.test/", "--blind", "oast.example", "--blind-header"]
    )
    assert args.blind_url == "oast.example"
    assert args.blind_header is True
    cfg = Config(blind_url=args.blind_url, blind_header=args.blind_header)
    assert cfg.blind_url == "oast.example"
    assert cfg.blind_header is True


def test_blind_is_off_by_default():
    args = build_parser().parse_args(["-u", "http://x.test/"])
    assert args.blind_url == ""
    assert args.blind_header is False
    assert Config().blind_url == ""
