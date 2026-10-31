"""The bench harness scans the shop the way it is meant to be scanned.

Two settings decide whether a surface can be measured at all, and each failed
silently in a different direction: the scan ran without writes, so the write
targets the surfaces exist for were dropped, and the replay authenticated on the
bearer plane alone, so a server-rendered page read it as an anonymous visitor.
"""

import inspect

import bench.juice as bench


def test_the_scan_is_run_with_writes_enabled():
    # The shop is a disposable instance reset between runs. Every stored sink on
    # it is reached by a write; without the flag the harness measures its own
    # read-only default and reports the application clean.
    assert "writes=True" in inspect.getsource(bench.scan_surface)
