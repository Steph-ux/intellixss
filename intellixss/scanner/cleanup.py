"""Remove what a writing scan created, and say plainly what it could not.

A scan that writes leaves records behind: comments, reviews, contact messages.
Until now the scanner simply abandoned them, and a person had to find them by
hand. Two rules make cleanup safe, and they are the reason it is a separate
module rather than another branch inside the plugins:

* It only ever deletes a URL that a plugin registered with an *identifier the
  target itself returned*. Nothing is guessed from a pattern such as
  ``/rest/products/1/reviews`` — a DELETE there removes reviews the scanner did
  not write.
* It never runs unless the scan was already allowed to write. A read-only scan
  wrote nothing, so it has nothing to remove and sends no DELETE at all.

What cannot be cleaned is reported, not silently dropped: a record whose create
response carried no identifier cannot be removed, and the report names the
surface so the operator knows to look.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

if TYPE_CHECKING:  # pragma: no cover
    from intellixss.http.client import HttpClient, WrittenRecord

# A DELETE that the target refuses as "not found" means the record is already
# gone (the scan removed it, or the app deleted it). Counting that as a failure
# would report an unclean target that is in fact clean.
_ALREADY_GONE = {200, 202, 204, 404, 410}

# The keys a create response uses to name the record it made. Anything else in
# the body (``productId``, ``reviewId``) names a *different* record, and
# deleting under it would remove a row the scan never wrote.
_ID_KEYS = ("id", "_id", "uuid", "pk")

# An identifier that is safe to place in a path segment. Numeric ids, UUIDs and
# the scanner's own markers qualify; a value carrying a slash, a dot segment or
# a scheme does not, because it would no longer name the record it came with.
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _id_from_json(body: str) -> str:
    """The record id a JSON body names, or "".

    Only a top-level key and one level of ``data``/``result`` are read: a value
    buried deeper belongs to a nested object, not to the record that was just
    created.
    """
    text = (body or "").strip()
    if not text or text[0] not in "{[":
        return ""
    try:
        doc = json.loads(text)
    except Exception:
        return ""
    candidates = []
    if isinstance(doc, dict):
        candidates.append(doc)
        for wrapper in ("data", "result", "record", "item"):
            inner = doc.get(wrapper)
            if isinstance(inner, dict):
                candidates.append(inner)
    for obj in candidates:
        for key in _ID_KEYS:
            value = obj.get(key)
            if isinstance(value, (int, str)) and str(value):
                return str(value)
    return ""


def _header(headers: Dict[str, str], name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def delete_url_from_response(
    create_url: str,
    body: str,
    headers: Dict[str, str],
    own_id: str = "",
) -> str:
    """The URL that removes the record a create response produced, or "".

    Resolution order is by strength of evidence: a ``Location`` header names the
    resource the server made, an id in the JSON body names it too, and an id the
    scanner chose itself is the last resort because the delete is then aimed at
    a record whose existence the server has not confirmed. When none of the three
    is present the answer is "", and the caller reports the write as not
    cleanable rather than guessing a path.
    """
    location = _header(headers, "location")
    if location:
        return urljoin(create_url, location)

    for candidate in (_id_from_json(body), own_id):
        if candidate and _SAFE_ID.match(candidate):
            parts = urlparse(create_url)
            base = urlunparse((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", "", ""))
            return f"{base}/{candidate}"
    return ""


async def clean_written(client: "HttpClient") -> List[Dict[str, object]]:
    """Attempt every registered removal, most recent first.

    Deleting in reverse creation order is not cosmetic: a surface that creates
    a parent and then children is only removable child-first, and the scan
    registers them in creation order.
    """
    from intellixss.http.client import writes_allowed

    out: List[Dict[str, object]] = []
    for rec in reversed(client.written):
        if not rec.cleanable:
            out.append(rec.describe())
            continue
        if not writes_allowed(client.config):
            # Defence in depth: the run should already have refused here, but a
            # cleanup must never be the one path that writes on a read-only
            # scan.
            out.append(rec.describe())
            continue
        status, _body, _hdrs, _final = await client.request(
            rec.delete_method, rec.delete_url
        )
        rec.removed = 1 if status in _ALREADY_GONE else 0
        if not rec.removed and not rec.reason:
            rec.reason = f"remove failed with status {status}"
        out.append(rec.describe())
    return out


def cleanup_summary(rows: List[Dict[str, object]]) -> Dict[str, object]:
    """Totals a report section can print without re-deriving them."""
    cleanable = [r for r in rows if r.get("cleanable")]
    return {
        "records": len(rows),
        "cleanable": len(cleanable),
        "removed": sum(int(r.get("removed") or 0) for r in rows),
        "uncleanable": len(rows) - len(cleanable),
        "surfaces": sorted({str(r.get("surface")) for r in rows}),
    }
