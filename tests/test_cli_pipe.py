"""Pipe / stdin ingestion contract.

The scanner has to behave the way a recon pipeline expects: ``cat urls | tool``
should scan each URL once, in order, with comments and blanks ignored — the
same shape ``gau``/``waybackurls``/``katana`` emit. These tests cover the pure
parsing helpers (no network) plus the stdin wiring in ``async_main``.
"""

import io
import sys

import pytest

from intellixss.cli import (
    _dedupe_preserving_order,
    _parse_url_lines,
    async_main,
    build_parser,
)


def test_parse_lines_skips_blanks_and_comments():
    text = "https://a.test/\n\n# a comment\n  https://b.test/?q=1  \n"
    assert _parse_url_lines(text) == ["https://a.test/", "https://b.test/?q=1"]


def test_dedupe_preserves_first_seen_order():
    urls = ["https://a.test/", "https://b.test/", "https://a.test/", "https://c.test/"]
    assert _dedupe_preserving_order(urls) == [
        "https://a.test/",
        "https://b.test/",
        "https://c.test/",
    ]


def test_pipe_and_dash_flags_parse():
    args = build_parser().parse_args(["--pipe"])
    assert args.pipe is True
    args = build_parser().parse_args(["-l", "-"])
    assert args.list == "-"


class _FakeStdin(io.StringIO):
    """A stdin stand-in that reports as a pipe (not a TTY)."""

    def isatty(self) -> bool:  # noqa: D401 - trivial
        return False


def _run_capturing_urls(monkeypatch, argv, stdin_text):
    """Drive ``async_main`` far enough to capture the URL list it assembled.

    ``Scanner`` is patched so no network happens: it records the URL and returns
    an empty result, which is all these tests assert on.
    """
    seen = []

    async def _stub_run_one(url, cfg, quiet):
        from intellixss.models import ScanResult

        seen.append(url)
        return ScanResult(target_url=url), 0

    monkeypatch.setattr("intellixss.cli._run_one", _stub_run_one)
    monkeypatch.setattr(sys, "stdin", _FakeStdin(stdin_text))
    # ``--json`` keeps stdout to one machine-readable document and avoids the
    # report/console paths that would need more of the environment.
    import asyncio

    asyncio.run(async_main(argv + ["--json"]))
    return seen


def test_stdin_is_read_when_piped_with_no_url(monkeypatch, capsys):
    seen = _run_capturing_urls(
        monkeypatch, [], "https://a.test/?x=1\nhttps://b.test/?y=2\n"
    )
    capsys.readouterr()
    assert seen == ["https://a.test/?x=1", "https://b.test/?y=2"]


def test_explicit_pipe_flag_reads_stdin(monkeypatch, capsys):
    seen = _run_capturing_urls(monkeypatch, ["--pipe"], "https://only.test/?z=3\n")
    capsys.readouterr()
    assert seen == ["https://only.test/?z=3"]


def test_url_flag_and_stdin_combine_and_dedupe(monkeypatch, capsys):
    seen = _run_capturing_urls(
        monkeypatch,
        ["-u", "https://a.test/?x=1", "--pipe"],
        "https://a.test/?x=1\nhttps://b.test/?y=2\n",
    )
    capsys.readouterr()
    # The seed URL also arriving on stdin must be scanned once, not twice.
    assert seen == ["https://a.test/?x=1", "https://b.test/?y=2"]
