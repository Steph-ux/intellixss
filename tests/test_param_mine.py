"""Parameter mining: names drawn from a page's own markup and inline JS.

Mining is only safe because every name it yields is later proven with a canary,
so these tests pin the two properties that keep the budget honest: it extracts
the names the page genuinely reveals (so the strongest candidates are tried
first), and it rejects noise and request machinery (so requests are not spent on
tokens that can never be a usable finding).
"""

from intellixss.discovery.param_mine import (
    COMMON_PARAMS,
    candidate_params,
    mine_param_names,
)


def test_mines_query_string_names_from_links():
    html = """<a href="/search?redirectUrl=/home&q=shoes">go</a>
              <a href='/p?productId=5&ref=email'>item</a>"""
    names = mine_param_names(html)
    assert "redirectUrl" in names
    assert "q" in names
    assert "ref" in names
    # ``productId`` is read as a name, but ``id``-shaped machinery is filtered.
    assert "productId" in names


def test_mines_form_field_names():
    html = """<form><input name="feedback"><textarea name="bio"></textarea>
              <select name="country"></select></form>"""
    names = mine_param_names(html)
    assert {"feedback", "bio", "country"} <= set(names)


def test_mines_js_param_reads():
    html = """<script>
      const p = new URLSearchParams(location.search);
      render(p.get('message'));
      var t = getParameterByName('theme');
      // leaked: $_GET['debug']
    </script>"""
    names = mine_param_names(html)
    assert {"message", "theme", "debug"} <= set(names)


def test_rejects_noise_and_structural_names():
    html = """<form>
      <input name="csrf_token" value="abc">
      <input name="authenticity_token">
      <input type="hidden" name="id" value="7">
      <input name="comment">
    </form>"""
    names = mine_param_names(html)
    assert "comment" in names
    for noise in ("csrf_token", "authenticity_token", "id"):
        assert noise not in names


def test_query_names_rank_before_dictionary():
    html = '<a href="/x?veryCustomParam=1">link</a>'
    candidates = candidate_params(html)
    # A name the page itself uses must be tried before any dictionary guess.
    assert candidates[0] == "veryCustomParam"
    # The dictionary still fills in conventional names the page never reveals.
    assert "redirect" in candidates


def test_candidate_list_is_deduped_and_ordered():
    html = '<a href="/x?q=1">dup</a>'  # ``q`` also lives in the dictionary
    candidates = candidate_params(html)
    assert candidates.count("q") == 1
    assert candidates[0] == "q"  # page use outranks the dictionary copy


def test_empty_html_yields_no_mined_names():
    assert mine_param_names("") == []
    # With no page signal, candidates are exactly the dictionary.
    assert candidate_params("", mine_limit=40, wordlist_limit=10) == list(
        COMMON_PARAMS[:10]
    )


def test_mine_limit_bounds_output():
    links = "".join(f'<a href="/x?p{i}=1">l</a>' for i in range(100))
    assert len(mine_param_names(links, limit=10)) == 10
