"""Character probe pure analysis."""

from intellixss.analysis.charprobe import analyze_char_probe, build_probe_string


def test_build_probe_string_roundtrip():
    uid = "abc123"
    probe = build_probe_string(uid)
    assert probe.startswith(f"xssP{uid}")
    assert probe.endswith(f"P{uid}xss")
    assert "<" in probe and ">" in probe


def test_analyze_allows_surviving_chars():
    uid = "zz99"
    probe = build_probe_string(uid)
    # reflect raw between markers
    body = f"<p>pre {probe} post</p>"
    result = analyze_char_probe("q", uid, body)
    assert result.reflected
    assert "<" in result.allowed_chars
    assert ">" in result.allowed_chars


def test_analyze_detects_encoded_angles():
    uid = "enc1"
    # Only markers and HTML-encoded angles in middle
    middle = "&lt;&gt;&quot;"
    body = f"xssP{uid}{middle}P{uid}xss"
    result = analyze_char_probe("q", uid, body)
    assert result.reflected
    # < or > should be encoded or blocked, not both freely allowed without encoding
    assert "<" not in result.allowed_chars or result.encoded_chars
