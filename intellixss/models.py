"""Core data models for IntelliXSS."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote_plus, urlparse


class InjectionContext(str, Enum):
    HTML_TEXT = "html_text"
    HTML_ATTR_DOUBLE = "html_attr_double"
    HTML_ATTR_SINGLE = "html_attr_single"
    HTML_ATTR_UNQUOTED = "html_attr_unquoted"
    HTML_ATTR_HREF = "html_attr_href"
    HTML_COMMENT = "html_comment"
    JS_STRING_DOUBLE = "js_string_double"
    JS_STRING_SINGLE = "js_string_single"
    JS_CODE = "js_code"
    JS_TEMPLATE = "js_template"
    JSON_VALUE = "json_value"
    CSS_VALUE = "css_value"
    TEXTAREA = "textarea"
    TITLE = "title"
    SCRIPT_TAG = "script_tag"
    URL_FRAGMENT = "url_fragment"
    JS_IN_ATTR = "js_in_attr"
    ENTITY_ENCODED_TAG = "entity_encoded_tag"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        """Human-friendly label for CLI / reports."""
        return _CONTEXT_LABELS.get(self, self.value)


_CONTEXT_LABELS = {
    InjectionContext.HTML_TEXT: "HTML text",
    InjectionContext.HTML_ATTR_DOUBLE: 'attribute value (double-quoted)',
    InjectionContext.HTML_ATTR_SINGLE: "attribute value (single-quoted)",
    InjectionContext.HTML_ATTR_UNQUOTED: "attribute value (unquoted)",
    InjectionContext.HTML_ATTR_HREF: "URL attribute (href/src)",
    InjectionContext.HTML_COMMENT: "HTML comment",
    InjectionContext.JS_STRING_DOUBLE: "JS string (double-quoted)",
    InjectionContext.JS_STRING_SINGLE: "JS string (single-quoted)",
    InjectionContext.JS_CODE: "JS code block",
    InjectionContext.JS_TEMPLATE: "JS template literal",
    InjectionContext.JSON_VALUE: "JSON value",
    InjectionContext.CSS_VALUE: "CSS block",
    InjectionContext.TEXTAREA: "textarea",
    InjectionContext.TITLE: "title tag",
    InjectionContext.SCRIPT_TAG: "script tag",
    InjectionContext.URL_FRAGMENT: "URL fragment (DOM)",
    InjectionContext.JS_IN_ATTR: "JS inside event attribute",
    InjectionContext.ENTITY_ENCODED_TAG: "inside an entity-encoded tag",
    InjectionContext.UNKNOWN: "unknown",
}


class FilterType(str, Enum):
    NO_FILTER = "no_filter"
    HTML_ENCODE = "html_encode"
    JS_ENCODE = "js_encode"
    URL_ENCODE = "url_encode"
    STRIP_TAGS = "strip_tags"
    STRIP_EVENTS = "strip_events"
    STRIP_SCRIPT = "strip_script"
    BLOCK_ANGLE = "block_angle"
    WAF_GENERIC = "waf_generic"
    WAF_CLOUDFLARE = "waf_cloudflare"
    WAF_SUCURI = "waf_sucuri"
    WAF_MODSEC = "waf_modsec"
    WAF_AKAMAI = "waf_akamai"
    WAF_AWS = "waf_aws"
    WAF_IMPERVA = "waf_imperva"
    WAF_F5_BIG_IP = "waf_f5_big_ip"
    WAF_FORTIWEB = "waf_fortiweb"
    WAF_BARRACUDA = "waf_barracuda"
    WAF_AZURE = "waf_azure"
    CSP = "csp"
    CSP_STRICT = "csp_strict"
    XSS_AUDITOR = "xss_auditor"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ")


class BlockReason(str, Enum):
    NONE = "none"
    HTTP_STATUS = "http_status"
    WAF_PAGE = "waf_page"
    CHAR_STRIPPED = "char_stripped"
    CHAR_ENCODED = "char_encoded"
    NO_REFLECTION = "no_reflection"
    FILTERED_PAYLOAD = "filtered_payload"
    NETWORK_ERROR = "network_error"
    CHALLENGE = "challenge"
    RATE_LIMITED = "rate_limited"


# ---------------------------------------------------------------------------
# Severity / CVSS 3.1
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# CVSS v3.1 base vector by (vulnerability type family, browser confirmed).
# Stored/blind vectors differ because the payload is delivered to other users.
_CVSS_TABLE: Dict[tuple, tuple] = {
    ("reflected", True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("reflected", False): (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("stored", True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    ("stored", False): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    ("stored_client", True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    ("stored_client", False): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    ("dom", True): (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("dom", False): (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("header_reflected", True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("header_reflected", False): (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("json_body", True): (7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    ("json_body", False): (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    ("graphql", True): (7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"),
    ("graphql", False): (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    ("graphql_stored", True): (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    ("graphql_stored", False): (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    ("file_upload_xss", True): (7.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    ("file_upload_xss", False): (5.4, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    ("open_redirect_xss", True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("open_redirect_xss", False): (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("stored_or_post", True): (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("stored_or_post", False): (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
}


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def compute_cvss(vuln_type: str, browser_confirmed: bool) -> Dict[str, Any]:
    """Return {score, severity, vector} for a finding."""
    key = (vuln_type, bool(browser_confirmed))
    if key not in _CVSS_TABLE:
        # Fall back to the reflected family, then to the unconfirmed baseline.
        cutoff = key[0]
        for (t, c), val in _CVSS_TABLE.items():
            if t == cutoff:
                key = (t, c)
                if c == bool(browser_confirmed):
                    break
        else:
            key = ("reflected", bool(browser_confirmed))
    score, vector = _CVSS_TABLE[key]
    return {
        "score": score,
        "severity": score_to_severity(score).value,
        "vector": vector,
    }


# ---------------------------------------------------------------------------
# Probe / context models
# ---------------------------------------------------------------------------


@dataclass
class CharProbeResult:
    param: str
    reflected: bool
    allowed_chars: Set[str] = field(default_factory=set)
    blocked_chars: Set[str] = field(default_factory=set)
    encoded_chars: Dict[str, str] = field(default_factory=dict)
    raw_reflection: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "reflected": self.reflected,
            "allowed_chars": "".join(sorted(self.allowed_chars)),
            "blocked_chars": "".join(sorted(self.blocked_chars)),
            "encoded_chars": self.encoded_chars,
        }


@dataclass
class ContextAnalysis:
    context: InjectionContext
    filters: List[FilterType] = field(default_factory=list)
    char_probe: Optional[CharProbeResult] = None
    reflection_snippet: str = ""
    confidence: float = 0.5
    waf_name: str = ""
    notes: List[str] = field(default_factory=list)
    # Rich detail used by the payload engine / reports
    # The quote a payload must use to close the injected string. This is the
    # JS string quote when the landing point is JS (``startTimer('…')`` inside
    # ``onload="…"``), and the HTML attribute quote otherwise.
    quote_char: str = ""  # '"' or "'" when inside a quoted attribute
    tag_name: str = ""  # enclosing tag when detectable
    attr_name: str = ""  # enclosing attribute when detectable
    decodes_once: bool = False  # app URL-decodes input once before echoing
    csp: Optional["_CspInfo"] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "context": self.context.value,
            "context_label": self.context.label,
            "filters": [f.value for f in self.filters],
            "char_probe": self.char_probe.to_dict() if self.char_probe else None,
            "reflection_snippet": self.reflection_snippet[:200],
            "confidence": round(self.confidence, 2),
            "waf_name": self.waf_name,
            "notes": self.notes,
            "quote_char": self.quote_char,
            "tag_name": self.tag_name,
            "attr_name": self.attr_name,
            "decodes_once": self.decodes_once,
            "csp": self.csp.to_dict() if self.csp else None,
        }
        return d


@dataclass
class _CspInfo:
    """Minimal CSP interpretation (kept private, surfaced via ContextAnalysis)."""

    present: bool = False
    strict: bool = False  # no unsafe-inline and no wildcard nonces → HTML sinks dead
    directives: Dict[str, str] = field(default_factory=dict)
    blocked_vectors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "strict": self.strict,
            "directives": self.directives,
            "blocked_vectors": self.blocked_vectors,
        }


@dataclass
class BlockDiagnosis:
    reason: BlockReason
    status: Optional[int] = None
    detail: str = ""
    signals: List[str] = field(default_factory=list)
    surviving_chars: List[str] = field(default_factory=list)
    blocked_chars: List[str] = field(default_factory=list)
    suggestion: str = ""  # actionable hint surfaced in the CLI

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reason": self.reason.value,
            "status": self.status,
            "detail": self.detail,
            "signals": self.signals,
            "surviving_chars": "".join(self.surviving_chars),
            "blocked_chars": "".join(self.blocked_chars),
            "suggestion": self.suggestion,
        }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class XSSFinding:
    url: str
    parameter: str
    method: str
    context: InjectionContext
    payload: str
    evidence: str
    browser_confirmed: bool = False
    impact: str = "high"
    vulnerability_type: str = "reflected"
    filters_bypassed: List[FilterType] = field(default_factory=list)
    confidence: float = 0.8
    block_diagnosis: Optional[BlockDiagnosis] = None
    # Trace / PoC
    marker: str = ""  # unique token that proved execution
    trigger: str = ""  # how the payload fired (dialog / hashchange / click …)
    waf: str = ""
    notes: List[str] = field(default_factory=list)
    verified_by: str = "reflection"  # reflection | browser | static | none
    # Alternative payloads to try in the browser when ``payload`` does not fire.
    payload_candidates: List[str] = field(default_factory=list)
    # Browser state the payload needs when its source is not the URL
    # (``document.referrer``, ``window.name``, cookies). Keyword args for
    # ``BrowserConfirmer.confirm``.
    seeds: Dict[str, Any] = field(default_factory=dict)
    # The POST body as the scanner sent it, when it built the whole record
    # itself. Empty for a GET, and for any body carrying a value the scanner
    # did not author (a CSRF token issued for another session): such a body is
    # not reproducible without that session, so the report says so rather than
    # printing a body that would fail.
    request_body: Dict[str, str] = field(default_factory=dict)

    @property
    def cvss(self) -> Dict[str, Any]:
        return compute_cvss(self.vulnerability_type, self.browser_confirmed)

    @property
    def severity(self) -> Severity:
        return score_to_severity(self.cvss["score"])

    @property
    def is_confirmed(self) -> bool:
        return self.browser_confirmed

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def verified_label(self) -> str:
        if self.browser_confirmed:
            return "CONFIRMED"
        if self.verified_by == "static":
            return "STATIC"
        return "REFLECTED"

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "context": self.context.value,
            "context_label": self.context.label,
            "payload": self.payload,
            "evidence": self.evidence,
            "browser_confirmed": self.browser_confirmed,
            "verified_by": self.verified_by,
            "verified_label": self.verified_label,
            "impact": self.impact,
            "vulnerability_type": self.vulnerability_type,
            "filters_bypassed": [f.value for f in self.filters_bypassed],
            "confidence": round(self.confidence, 2),
            "cvss": self.cvss,
            "severity": self.severity.value,
            "marker": self.marker,
            "trigger": self.trigger,
            "waf": self.waf,
            "notes": self.notes,
            "request_body": dict(self.request_body),
            "reproduce": reproduce_command(self),
        }
        if self.block_diagnosis:
            d["block_diagnosis"] = self.block_diagnosis.to_dict()
        return d


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    data: Dict[str, str] = field(default_factory=dict)
    source: str = "seed"
    # Page the form was found on. A submission redirects to a thank-you page,
    # so this is where the stored value is actually rendered afterwards.
    source_url: str = ""


# ---------------------------------------------------------------------------
# Outcomes / results
# ---------------------------------------------------------------------------


@dataclass
class ProbeOutcome:
    """Outcome of one payload attempt — success or structured block info."""

    success: bool
    payload: str
    reflected: bool
    status: int
    finding: Optional[XSSFinding] = None
    diagnosis: Optional[BlockDiagnosis] = None
    decoding_layer: int = 0  # how many decode passes were needed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "payload": self.payload,
            "reflected": self.reflected,
            "status": self.status,
            "decoding_layer": self.decoding_layer,
            "finding": self.finding.to_dict() if self.finding else None,
            "diagnosis": self.diagnosis.to_dict() if self.diagnosis else None,
        }


@dataclass
class ScanStats:
    """Counters surfaced in the CLI summary."""

    requests: int = 0
    payloads_sent: int = 0
    reflections: int = 0
    browser_navigations: int = 0
    rate_limited: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def duration(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at or 0.0
        return max(0.0, end - self.started_at)

    @property
    def req_per_sec(self) -> float:
        d = self.duration
        return round(self.requests / d, 2) if d > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests": self.requests,
            "payloads_sent": self.payloads_sent,
            "reflections": self.reflections,
            "browser_navigations": self.browser_navigations,
            "rate_limited": self.rate_limited,
            "duration_s": round(self.duration, 2),
            "req_per_sec": self.req_per_sec,
        }


@dataclass
class ScanResult:
    target_url: str
    findings: List[XSSFinding] = field(default_factory=list)
    diagnoses: List[BlockDiagnosis] = field(default_factory=list)
    outcomes: List[ProbeOutcome] = field(default_factory=list)
    targets_tested: int = 0
    errors: List[str] = field(default_factory=list)
    waf: str = ""
    stats: ScanStats = field(default_factory=ScanStats)

    @property
    def confirmed(self) -> List[XSSFinding]:
        return [f for f in self.findings if f.browser_confirmed]

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def counts_by_severity(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "engine": _engine_version(),
            "waf": self.waf,
            "finding_count": len(self.findings),
            "confirmed_count": len(self.confirmed),
            "max_severity": self.max_severity.value if self.max_severity else None,
            "severity_counts": self.counts_by_severity(),
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "diagnoses": [d.to_dict() for d in self.diagnoses],
            "targets_tested": self.targets_tested,
            "errors": self.errors,
        }


def _engine_version() -> str:
    try:
        from intellixss import __version__

        return __version__
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def mark_of(payload: str) -> str:
    """Return the unique ixmark token embedded in *payload* ('' if none).

    The token is normally literal, but a payload written for a context that
    escapes quotes carries it as ``String.fromCharCode(…)`` so that no quote
    ever has to survive. That form is decoded here before the search: the
    payload does carry a marker, it just does not spell it out, and refusing it
    dropped the one candidate that executes there.
    """
    text = payload or ""
    m = re.search(r"ixm([0-9a-f]{6,})", text)
    if m:
        return m.group(0)
    for args in re.findall(r"fromCharCode\(\s*([0-9,\s]+)\)", text):
        try:
            decoded = "".join(chr(int(n)) for n in args.split(",") if n.strip())
        except (ValueError, OverflowError):
            continue
        m2 = re.search(r"ixm([0-9a-f]{6,})", decoded)
        if m2:
            return m2.group(0)
    return ""


# A value that still carries a percent-escape is read by the *server* as that
# escape: ``%3C`` becomes ``<`` before the application sees it, and a private
# repeater re-sends the bytes. Such a value must not be quoted again, or the
# payload arrives double-encoded and the reproduction is of a different
# request than the one the scanner sent.
_ESCAPED_VALUE = re.compile(r"%[0-9A-Fa-f]{2}")


def _reproduce_url(finding: "XSSFinding") -> str:
    """The URL to paste into a browser or ``curl`` to fire this finding."""
    url = finding.url or ""
    if finding.method.upper() != "GET" or not finding.parameter:
        return url
    pattern = r"([?&])" + re.escape(finding.parameter) + r"=([^&#]*)"
    m = re.search(pattern, url)
    if not m:
        return url
    value = finding.payload or ""
    # A value that kept its own percent-escapes must be written raw, or a
    # shell would encode the ``%`` of ``%3C`` and the replayed request would
    # differ from the one that was sent. Otherwise every character outside the
    # unreserved set is encoded, which is what the client does on the wire: a
    # quote left literal would be a different URL than the one that fired.
    if not _ESCAPED_VALUE.search(value):
        # ``quote_plus`` and not ``quote``: a query component encodes a space
        # as ``+``, which is what the client puts on the wire.
        value = quote_plus(value, safe="")
    return url[: m.start(2)] + value + url[m.end(2) :]


_SESSION_FIELD = re.compile(
    r"csrf|xsrf|nonce|token|authenticity|^_session|sid$|^session", re.IGNORECASE
)


def _shell_quote(value: str) -> str:
    """Quote for a POSIX shell. A single quote cannot appear inside single
    quotes, and a payload is chosen precisely because it carries quotes, so
    every ``'`` is closed, escaped and reopened."""
    return "'" + value.replace("'", "'\\''") + "'"


def _form_body(finding: "XSSFinding") -> str:
    """The POST body as a shell-quoted ``key=value`` sequence, '' if unknown."""
    body = dict(finding.request_body or {})
    if not body:
        return ""
    body[finding.parameter] = finding.payload
    return " ".join(
        f"--data-urlencode {_shell_quote(f'{k}={v}')}" for k, v in body.items()
    )


def reproduce_command(finding: "XSSFinding") -> str:
    """A command that replays the finding exactly as the scanner sent it.

    A report a reader cannot replay is an assertion, not evidence: the reader
    has to be able to fire on the same endpoint with the same value before
    believing the finding. The cookie and other session headers are
    deliberately absent - they belong to the operator, not to the document.
    """
    url = _reproduce_url(finding)
    method = (finding.method or "GET").upper()
    quoted = _shell_quote(url)
    if method == "GET":
        return f"curl -sS {quoted}"

    body = _form_body(finding)
    if not body:
        # The body is not ours to rebuild: it carried a token minted for the
        # scanning session. Naming that beats printing a request that fails.
        return (
            f"# POST {url} - replay from a session that holds this account: "
            f"the body carries a per-session token the scanner cannot reproduce"
        )
    if any(_SESSION_FIELD.search(k) for k in finding.request_body):
        note = (
            f"\n# replace the {'/'.join(k for k in finding.request_body if _SESSION_FIELD.search(k))}"
            " value with the one from your own session"
        )
    else:
        note = ""
    return f"curl -sS -X {method} {quoted} {body}{note}"

