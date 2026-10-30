"""Field-shape detection: a value that must look like a link to be accepted.

Some forms police the *shape* of a field rather than its characters — a
"Website" input with ``pattern="(http:|https:).+"`` rejects anything that is not
a URL before the handler runs, while the sink behind that check still renders
whatever it was given. The wrapping below carries a value past that check
verbatim, so the injection still reaches the sink and stays locatable in the
echo (the template is kept by the caller for that reason).
"""

from __future__ import annotations

import re

URL_SHAPE = "http://ixv.example/{value}"


def field_attr(html: str, field: str) -> str:
    """The opening tag of the input/textarea named *field*, or ``""``."""
    if not html:
        return ""
    m = re.search(
        rf'<(?:input|textarea)\b[^>]*name=["\']{re.escape(field)}["\'][^>]*>',
        html,
        re.I,
    )
    return m.group(0) if m else ""


def wants_url(field_html: str) -> bool:
    """Whether a field's own markup declares a URL shape.

    Both the declarative ``pattern="(http:|https:).+"`` (PortSwigger's website
    field, and the common clone of it) and ``type="url"`` are read here. The
    name-based fallback stays because that is all an app that validates on the
    server side exposes in its markup.
    """
    if not field_html:
        return False
    if re.search(r"pattern\s*=\s*[\"'][^\"']*https?:", field_html, re.I):
        return True
    if re.search(r"type\s*=\s*[\"']url[\"']", field_html, re.I):
        return True
    return False
