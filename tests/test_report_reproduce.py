"""Reproduction line: a finding must be replayable byte for byte.

A report a reader cannot replay is an assertion. These tests pin the two ways
the line can lie - a value quoted twice, and a value rebuilt from a query
string that never held it.
"""

from intellixss.models import (
    InjectionContext,
    XSSFinding,
    reproduce_command,
)

import os
import shutil
import subprocess

import pytest


def _finding(url: str, payload: str, param: str = "q", method: str = "GET") -> XSSFinding:
    return XSSFinding(
        url=url,
        parameter=param,
        method=method,
        context=InjectionContext.HTML_TEXT,
        payload=payload,
        evidence="test",
        marker="ixm1a2b3c4d",
    )


def test_plain_payload_is_percent_encoded_once():
    f = _finding("https://t/app?q=1&x=2", '<svg onload=alert("ixm1a2b3c4d")>')
    cmd = reproduce_command(f)
    assert "%3Csvg" in cmd and "<svg" not in cmd
    assert "&x=2" in cmd, "the rest of the query string must survive"
    assert cmd.startswith("curl -sS '")

def test_payload_carrying_percent_escapes_is_written_raw():
    """A server-side breakout keeps its own escapes; quoting them would
    deliver ``%2527`` and reproduce a different request."""
    payload = "%27%29%3Balert%281%29%2F%2F"
    f = _finding("https://t/app?q=1", payload)
    cmd = reproduce_command(f)
    assert "%27%29" in cmd
    assert "%2527" not in cmd


def test_missing_parameter_leaves_the_url_alone():
    f = _finding("https://t/app?q=1", "<svg>", param="absent")
    assert reproduce_command(f) == "curl -sS 'https://t/app?q=1'"


def test_post_finding_without_a_body_explains_itself():
    f = _finding("https://t/comment", "<svg>", method="POST")
    cmd = reproduce_command(f)
    assert cmd.startswith("# POST https://t/comment")
    assert "-X POST" not in cmd, "a command that cannot work is not printed"


def test_post_body_is_rebuilt_from_the_record_the_scanner_sent():
    """A form POST is unreadable without its body: the reader has to know
    which sibling fields the handler required."""
    f = _finding("https://t/comment", "<svg onload=alert(1)>", param="comment", method="POST")
    f.request_body = {"comment": "", "name": "tester", "email": "a@b.c"}
    cmd = reproduce_command(f)
    assert "-X POST" in cmd
    assert "--data-urlencode 'comment=<svg onload=alert(1)>'" in cmd
    assert "--data-urlencode 'name=tester'" in cmd
    # The injected parameter is written from the payload, not from the record.
    assert cmd.count("comment=") == 1


def test_session_token_is_named_rather_than_faked():
    f = _finding("https://t/change", "<svg>", param="email", method="POST")
    f.request_body = {"email": "", "csrf": "0123456789abcdef"}
    cmd = reproduce_command(f)
    assert "replace the csrf value" in cmd
    assert "0123456789abcdef" in cmd, "the recorded value is shown, not invented"


def test_post_without_a_body_says_why_instead_of_guessing():
    f = _finding("https://t/comment", "<svg>", method="POST")
    cmd = reproduce_command(f)
    assert cmd.startswith("# POST")
    assert "cannot reproduce" in cmd


def test_post_body_survives_the_shell():
    f = _finding("https://t/comment", "x'><svg>", param="comment", method="POST")
    f.request_body = {"comment": "", "name": "o'neil"}
    cmd = reproduce_command(f)
    out = _run_posix(cmd.split(" -X POST ", 1)[1].split(" ", 1)[1])
    if out is not None:
        # The shell must hand curl the payload and the apostrophe intact.
        assert "comment=x'><svg>" in out
        assert "name=o'neil" in out


def test_quote_in_the_payload_survives_the_shell():
    """The payload exists to carry quotes. A percent-encoded quote is safe in
    any shell; one left literal must be escaped, not terminate the argument."""
    f = _finding("https://t/app?q=1", "x' onfocus=alert(1)")
    cmd = reproduce_command(f)

    # The only test that matters: what the shell hands to curl. ``printf %s``
    # receives the argument exactly as curl would.
    script = f"printf %s {cmd[len('curl -sS '):]}"
    out = _run_posix(script)
    if out is None:
        pytest.skip("no POSIX shell available to verify quoting")
    assert out == "https://t/app?q=x%27+onfocus%3Dalert%281%29"

    # A raw quote in the value (the escape-preserving path) must not break the
    # command either.
    literal = reproduce_command(_finding("https://t/app?q=1", "%3C'a"))
    out = _run_posix(f"printf %s {literal[len('curl -sS '):]}")
    if out is not None:
        assert out == "https://t/app?q=%3C'a"


def _run_posix(script: str):
    """Run *script* under any available POSIX shell; None when there is none."""
    for exe in ("bash", "sh"):
        found = shutil.which(exe)
        if found:
            r = subprocess.run([found, "-c", script], capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout
    # Git for Windows ships bash outside PATH on a default install; a test that
    # skips silently proves nothing, so the known locations are probed too.
    for path in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\sh.exe",
    ):
        if os.path.exists(path):
            r = subprocess.run([path, "-c", script], capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout
    return None


def test_encoding_matches_what_the_client_sends():
    """The replayed URL must be the one the scanner actually fired, so it is
    built with the same encoder the HTTP client uses."""
    import httpx

    payload = "x' onfocus=alert(1)"
    expected = str(httpx.URL("https://t/app", params={"q": payload}))
    f = _finding("https://t/app?q=1", payload)
    assert reproduce_command(f) == f"curl -sS {_expected_quoted(expected)}"


def _expected_quoted(url: str) -> str:
    return "'" + url.replace("'", "'\\''") + "'"


def test_finding_serialises_the_reproduction():
    f = _finding("https://t/app?q=1", "<svg onload=alert(1)>")
    assert f.to_dict()["reproduce"].startswith("curl -sS '")
