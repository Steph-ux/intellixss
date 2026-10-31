"""The field a stored record is written through is recognised by name.

``username`` is the account's display name: an application renders it on the
profile page and in every page header, so it is stored content in exactly the
sense a comment is. It was missing from the list of field names the stored pass
follows, which made the pass skip a form whose only stored field is the
username — the write happens, the page renders the record, and nothing looks.
"""

from intellixss.plugins.stored_xss import STORE_FIELDS


def test_the_display_name_is_a_stored_field():
    assert "username" in STORE_FIELDS


def test_the_fields_that_are_not_stored_content_stay_out():
    # Structural fields drive the request rather than carry the record; an
    # email or a password identifies the account and is never rendered back.
    for field in ("email", "password", "csrf", "id", "role"):
        assert field not in STORE_FIELDS, field
