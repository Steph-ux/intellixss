"""A backslash-escaped delimiter is beatable, so it must not read as "blocked".

On the onclick lab the apostrophe comes back as ``\\'``. The character is
present — the app escaped it after reading the input — so its HTML entity
arrives after the escaper ran and the browser turns it back into a real quote.
Calling that "blocked" told the generator to give up on a delimiter it could
deliver, which is why the lab sat at static-only.
"""

from intellixss.analysis.charprobe import measure_single_char
from intellixss.payloads.generator import generate_payloads, make_marker

UID = "abcd1234"
MARKER = make_marker(UID)


def _echo(inner: str) -> str:
    return f'<a onclick="track(S{UID}A{inner}Z{UID}E)">x</a>'


def test_backslash_prefixed_quote_is_escaped_not_blocked():
    assert measure_single_char("website", UID, "'", _echo("\\'")) == "escaped"


def test_verbatim_quote_is_allowed():
    assert measure_single_char("website", UID, "'", _echo("'")) == "allowed"


def test_entity_encoded_quote_is_encoded():
    assert measure_single_char("website", UID, "'", _echo("&apos;")) == "encoded"


def test_missing_quote_is_blocked():
    assert measure_single_char("website", UID, "'", _echo("")) == "blocked"


def test_escaped_quote_yields_an_entity_payload():
    """An escaped delimiter has to reach the generator as recoverable."""
    from intellixss.models import CharProbeResult, FilterType, InjectionContext

    probe = CharProbeResult(
        param="website",
        reflected=True,
        allowed_chars=set("abcxyz"),
        blocked_chars=set("<"),
        encoded_chars={"'": "&apos;"},
        raw_reflection="",
    )
    payloads = generate_payloads(
        InjectionContext.JS_IN_ATTR,
        [FilterType.NO_FILTER],
        char_probe=probe,
        limit=24,
        marker=MARKER,
        quote_char="'",
    )
    assert any("&apos;" in p for p in payloads), payloads


def test_escaped_non_delimiter_counts_as_blocked():
    """Only a delimiter has an entity that survives a backslash escape.

    ``\\(`` stays ``\\(``: there is no spelling that turns it back into an
    opening parenthesis. Recording it as a workaround handed the generator a
    character it could not emit, and the candidate budget went on payloads that
    could never run.
    """
    from intellixss.models import CharProbeResult
    from intellixss.scanner.orchestrator import _merge_char_probe

    base = CharProbeResult(
        param="comment",
        reflected=True,
        allowed_chars=set("abc"),
        blocked_chars=set(),
        encoded_chars={},
        raw_reflection="",
    )
    merged = _merge_char_probe(base, "comment", {"(": "escaped", "'": "escaped"})
    assert "'" in merged.encoded_chars
    assert "(" in merged.blocked_chars
    assert "(" not in merged.encoded_chars
