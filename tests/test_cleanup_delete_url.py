"""The delete URL a create response actually licenses.

Cleanup is only safe if the URL it deletes is one the target pointed at. These
tests pin the resolution rules against the response shapes real applications
return, and against the shapes that must resolve to nothing:

* a JSON body naming the new record's id (``{"id": 42}``, ``{"data": {"id":
  "42"}}``);
* a ``Location`` header for the created resource;
* an id the scanner itself generated and posted, which is the only case where
  a path can be built without the response saying so — and it is still the
  scanner's own value, so the delete can only reach its own record;
* anything else resolves to no URL at all, so no pattern-derived guess can
  delete somebody else's record.
"""

from intellixss.scanner.cleanup import delete_url_from_response


def test_an_id_in_the_json_body_names_the_created_record():
    url = delete_url_from_response(
        "https://t/rest/products/1/reviews",
        '{"id": 42, "message": "x"}',
        {"content-type": "application/json"},
    )
    assert url == "https://t/rest/products/1/reviews/42"


def test_an_id_nested_under_data_is_found():
    url = delete_url_from_response(
        "https://t/api/comments",
        '{"status": "success", "data": {"id": "abc-7"}}',
        {},
    )
    assert url == "https://t/api/comments/abc-7"


def test_a_location_header_wins_over_a_body():
    url = delete_url_from_response(
        "https://t/api/comments",
        '{"id": 1}',
        {"Location": "https://t/api/comments/99"},
    )
    assert url == "https://t/api/comments/99"


def test_a_relative_location_is_resolved_against_the_create_url():
    url = delete_url_from_response(
        "https://t/api/comments", "", {"location": "/api/comments/99"}
    )
    assert url == "https://t/api/comments/99"


def test_an_id_the_scanner_chose_is_used_when_nothing_comes_back():
    url = delete_url_from_response(
        "https://t/api/comments", "", {}, own_id="ixc1234"
    )
    assert url == "https://t/api/comments/ixc1234"


def test_an_html_page_with_no_id_resolves_to_nothing():
    """The most common case. Guessing here is what would delete a user's row."""
    url = delete_url_from_response(
        "https://t/post/comment", "<html><body>Thanks</body></html>", {}
    )
    assert url == ""


def test_an_id_from_an_unrelated_key_is_not_used():
    url = delete_url_from_response(
        "https://t/api/comments",
        '{"productId": 3, "reviewId": 4}',
        {},
    )
    assert url == ""


def test_a_non_numeric_non_uuid_id_is_refused():
    """A value that could be a path fragment is not put into a URL."""
    url = delete_url_from_response(
        "https://t/api/comments", '{"id": "../admin"}', {}
    )
    assert url == ""


def test_a_create_url_with_a_query_string_keeps_its_shape():
    """``POST /api/x?token=…`` deletes under the path, not the query."""
    url = delete_url_from_response(
        "https://t/api/comments?module=1", '{"id": 7}', {}
    )
    assert url == "https://t/api/comments/7"
