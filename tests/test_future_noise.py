"""Benign orphaned-navigation-future suppression.

A live run against a heavy HTTPS site left Playwright navigation futures
orphaned when probes were cancelled (the stored pass hitting its time cap),
printing "Future exception was never retrieved" tracebacks. The predicate
behind the loop exception handler must drop exactly those and nothing else.
"""

from intellixss.cli import _is_benign_orphan_future


def test_err_aborted_is_benign():
    exc = RuntimeError(
        'net::ERR_ABORTED; maybe frame was detached?\n'
        '  - navigating to "https://isoceltelecom.com/", waiting until "load"'
    )
    assert _is_benign_orphan_future("Future exception was never retrieved", exc)


def test_nav_timeout_is_benign():
    exc = TimeoutError(
        'Timeout 12000ms exceeded.\n'
        '  - navigating to "https://isoceltelecom.com/?s=x", waiting until "domcontentloaded"'
    )
    assert _is_benign_orphan_future("Future exception was never retrieved", exc)


def test_target_closed_is_benign():
    exc = RuntimeError("Target page, context or browser has been closed")
    assert _is_benign_orphan_future("Future exception was never retrieved", exc)


def test_other_future_error_not_suppressed():
    exc = ValueError("something genuinely wrong in our code")
    assert not _is_benign_orphan_future("Future exception was never retrieved", exc)


def test_non_future_message_not_suppressed():
    # A real unhandled exception on the loop must always reach the handler, even
    # if its text happens to mention a navigation.
    exc = RuntimeError('navigating to "x"')
    assert not _is_benign_orphan_future("Task exception was never retrieved", exc)
