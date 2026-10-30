"""Discovery must respect user URL path scope."""

from intellixss.discovery.targets import _same_scope, _is_site_root, _path_prefix


def test_level1_scope_excludes_level3():
    seed = "https://xss-game.appspot.com/level1"
    assert _same_scope("https://xss-game.appspot.com/level1/frame", seed)
    assert not _same_scope("https://xss-game.appspot.com/level3/frame", seed)
    assert not _same_scope("https://xss-game.appspot.com/level4/frame", seed)
    assert not _same_scope("https://xss-game.appspot.com/level5/frame/signup", seed)


def test_root_scope_allows_all_levels():
    seed = "https://xss-game.appspot.com/"
    assert _is_site_root(seed)
    assert _same_scope("https://xss-game.appspot.com/level1/frame", seed)
    assert _same_scope("https://xss-game.appspot.com/level4/frame", seed)


def test_path_prefix_level1():
    assert _path_prefix("https://xss-game.appspot.com/level1") == "/level1"
    assert _path_prefix("https://xss-game.appspot.com/level1/") == "/level1"
    assert _path_prefix("https://xss-game.appspot.com/") == "/"
