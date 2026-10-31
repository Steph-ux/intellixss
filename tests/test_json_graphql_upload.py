from intellixss.plugins.graphql_xss import _gql_urls, gql_payloads
from intellixss.plugins.json_xss import discover_json_endpoints, json_payloads
from intellixss.plugins.upload_xss import discover_upload_forms, upload_payloads

MARKER = "ixm0a1b2c3d"


def test_discover_json_from_html():
    html = """
    <script>
      fetch('/api/comments', { method: 'POST', body: JSON.stringify({x:1}) });
      axios.post('/api/v1/search', {});
    </script>
    """
    eps = discover_json_endpoints("https://ex.com/app", html)
    assert any("/api/comments" in e for e in eps)
    assert any("search" in e for e in eps)


def test_json_payloads_carry_the_marker():
    payloads = json_payloads(MARKER)
    assert payloads
    assert all(MARKER in p for p in payloads)
    assert not any("alert(1)" in p for p in payloads)


def test_gql_urls():
    urls = _gql_urls("https://ex.com/home")
    assert any(u.endswith("/graphql") for u in urls)
    assert all(MARKER in p for p in gql_payloads(MARKER))


def test_upload_form_discovery():
    html = """
    <form action="/avatar" method="post" enctype="multipart/form-data">
      <input type="file" name="avatar"/>
      <input type="submit"/>
    </form>
    """
    forms = discover_upload_forms(html, "https://ex.com/")
    assert len(forms) == 1
    assert forms[0]["file_field"] == "avatar"
    assert "avatar" in forms[0]["action"] or forms[0]["action"].endswith("/avatar")


def test_upload_payloads_nonempty():
    payloads = upload_payloads(MARKER)
    assert len(payloads) >= 3
    assert all(MARKER.encode() in content for *_rest, content in payloads)
