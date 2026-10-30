"""The URL-shape retry must not be spent on values that are not a shape mistake.

A field with its own validator rejects a payload because the payload is the
payload, not because the tester typed a bad link. On a handler where one POST
costs ten seconds, the retry is the parameter's entire request budget — and it
is spent before the ladder gets its first attempt.
"""

import asyncio

import pytest

from intellixss.models import ScanResult, ScanTarget
from intellixss.scanner.orchestrator import Scanner


class _Recorder:
    """Counts inject calls and answers 400 to everything."""

    def __init__(self):
        self.calls = []

    async def inject(self, url, param, value, method="GET", base_data=None, **_kw):
        self.calls.append((method, value))
        return 400, "Invalid value", {}, url


def _target(method):
    return ScanTarget(
        url="https://t.test/post/comment",
        method=method,
        params=["website"],
        data={"comment": "x"} if method == "POST" else None,
        source="form",
    )


@pytest.mark.parametrize("value", ["ixmbc53d0ea", "xssPbc53d0ea<>\"'`{}[]", "<img src=x onerror=alert(1)>"])
async def test_post_rejection_is_not_retried_with_a_url_shape(value):
    client = _Recorder()
    s = Scanner.__new__(Scanner)
    st, _b, _h, _f = await Scanner._inject(
        s, client, _target("POST"), "website", value
    )
    assert st == 400
    assert len(client.calls) == 1, client.calls


async def test_get_rejection_of_a_probe_is_retried_with_a_url_shape():
    """A URL-shaped field on a GET still gets its second chance."""
    client = _Recorder()
    s = Scanner.__new__(Scanner)
    await Scanner._inject(s, client, _target("GET"), "website", "ixmbc53d0ea")
    assert len(client.calls) == 2
    assert client.calls[1][1].startswith("http://")


async def test_get_rejection_of_a_markup_payload_is_not_retried():
    client = _Recorder()
    s = Scanner.__new__(Scanner)
    await Scanner._inject(s, client, _target("GET"), "q", "<svg/onload=alert(1)>")
    assert len(client.calls) == 1
