"""The console must not depend on the host code page.

Under the PowerShell 5 host, rich detected a "legacy Windows" console and
wrote styled text straight to a cp1252 stream. The CLI's own strings contain
non-ASCII characters, so the first styled line raised UnicodeEncodeError and
the scan died after it had already done the work - the worst possible moment
to lose output.

These tests pin the contract: the console refuses legacy mode, and it can
render every string the renderers produce when stdout cannot encode anything
outside ASCII.
"""

import io
import sys

from intellixss.cli import _console
from intellixss.models import Severity


class _Cp1252(io.TextIOBase):
    """A stdout that rejects every non-ASCII character, like cp1252 does."""

    encoding = "cp1252"

    def __init__(self) -> None:
        self.buffer_out: list[str] = []

    def write(self, text: str) -> int:
        text.encode("cp1252")  # raises for the characters rich would send
        self.buffer_out.append(text)
        return len(text)

    def isatty(self) -> bool:
        return True


def test_console_does_not_enter_legacy_windows_mode(monkeypatch):
    monkeypatch.setattr(sys, "stdout", _Cp1252())
    console = _console()
    assert console.legacy_windows is False


def test_styled_ascii_output_survives_a_cp1252_stream(monkeypatch):
    # A styled line is what legacy_windows_render writes straight to the
    # stream; every non-ASCII character that reaches it must have been
    # converted to something cp1252 can encode.
    sink = _Cp1252()
    monkeypatch.setattr(sys, "stdout", sink)
    console = _console()
    console.print("Severity", Severity.CRITICAL.value, style="bold red")
    console.print("\u2014 em dash", style="bold")  # rich maps it to "-"
    assert sink.buffer_out
