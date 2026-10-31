"""A stored value that never echoes is a problem with the record, not the payload.

The lab `stored/lab-html-context-nothing-encoded` is the easiest stored XSS in
the set: the comment form takes arbitrary markup and renders it unencoded. The
scanner reported it CLEAN, with no finding of any kind. The payload was never
the issue — the record never appeared.

The write target is chosen from the field names a form offers, and the form that
answers this lab carries ``comment``, ``name``, ``email`` and ``website``. Whichever
of those is picked, the *other three* are sent empty, and the handler drops the
comment: a comment with no author is not a comment. The canary was never stored,
so every payload looked inert.

The rule pinned here: when no record appears, the write is retried once with the
fields the form did not target filled with plausible values. The silence is the
trigger — nothing extra is sent on a write that already worked — so the cost is
one request on the cases that are currently false negatives, and none on the
cases that already pass.

These are unit tests on the filler itself, because that is where the decision
lives; the lab is the live proof.
"""

from intellixss.plugins.stored_xss import (
    _filler_for_field,
    _fill_untargeted_fields,
)


FIELDS = ["comment", "name", "email", "website"]


def test_the_targeted_field_is_never_overwritten():
    """A plausible value in the field under test would hide the payload."""
    data = _fill_untargeted_fields({"comment": ""}, FIELDS, "comment")
    assert data["comment"] == ""
    assert "PLACEHOLDER" not in data["comment"]


def test_every_untargeted_field_receives_a_value():
    data = _fill_untargeted_fields({"comment": ""}, FIELDS, "comment")
    for field in ("name", "email", "website"):
        assert data[field], f"{field} was left empty and the record was dropped"


def test_an_email_field_gets_something_that_is_an_email():
    """A handler that validates the shape rejects a sentence."""
    assert "@" in data_value("email") and "." in data_value("email").split("@")[1]


def test_a_website_field_gets_a_url_not_a_bare_word():
    value = data_value("website")
    assert value.startswith(("http://", "https://"))


def test_a_name_field_gets_a_short_plain_name():
    value = data_value("name")
    assert value and len(value) <= 32 and "@" not in value


def test_a_message_like_field_gets_a_sentence():
    value = _filler_for_field("message")
    assert len(value.split()) >= 3


def test_an_unknown_field_gets_a_non_empty_default():
    assert _filler_for_field("custom_field_xyz")


def test_existing_untargeted_values_are_kept():
    """A form the scan already filled with real values must not be rewritten."""
    data = _fill_untargeted_fields(
        {"comment": "", "name": "wiener"}, FIELDS, "comment"
    )
    assert data["name"] == "wiener"


def test_a_field_already_carrying_the_payload_is_kept():
    data = _fill_untargeted_fields({}, FIELDS, "comment", value="<img src=x>")
    assert data["comment"] == "<img src=x>"


def data_value(field: str) -> str:
    return _fill_untargeted_fields({"comment": ""}, FIELDS, "comment")[field]
