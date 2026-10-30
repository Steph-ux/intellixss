"""A placeholder must be a value the handler's own validator accepts.

The lab's comment form validates the whole record and answers 400 naming the
field it dislikes. Filling an address field with ``test`` makes every POST fail
before the record is stored, so no field on that form can be tested — the scan
reports the parameter as blocked when the handler never even saw a value.
"""

from intellixss.discovery.targets import extract_forms

PAGE = "https://t.test/post?postId=1"

# The real shape: the address field declares no type, and no field is marked
# required — the validator lives behind the handler.
FORM = """
<form action="/post/comment" method="POST">
  <input name="csrf" value="tok">
  <input name="postId" value="1">
  <textarea name="comment"></textarea>
  <input name="name">
  <input name="email">
  <input name="website">
  <button type="submit">Post</button>
</form>
"""


def test_untyped_address_field_is_filled_with_an_address():
    (target,) = extract_forms(FORM, PAGE)
    assert target.data["email"] == "scan@example.com"


def test_every_field_is_filled_with_a_typed_value():
    (target,) = extract_forms(FORM, PAGE)
    assert target.data["website"] == "http://example.com"
    assert target.data["comment"] == "test"
    assert target.data["postId"] == "1"


def test_regex_branch_fills_the_same_values_without_bs4():
    """The fallback parser must behave like the parser it stands in for."""
    import intellixss.discovery.targets as T

    saved = T.HAS_BS4
    try:
        T.HAS_BS4 = False
        (target,) = extract_forms(FORM, PAGE)
    finally:
        T.HAS_BS4 = saved
    assert target.data["email"] == "scan@example.com"
    assert target.data["website"] == "http://example.com"
