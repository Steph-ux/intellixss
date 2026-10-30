"""AngularJS escape selection is a property of the app, not a payload list.

The old rule was "a literal ``ng-app`` plus a versioned ``angular.js``", and one
expression family. Both halves are wrong on real apps: an app bootstrapped from
script has no ``ng-app`` attribute yet compiles perfectly, and a ``self``-only
CSP removes ``Function`` from the sandbox entirely so every
``constructor('…')`` candidate is dead before it is sent.

These tests pin the decision, not the strings: which root the page declares,
whether CSP mode is on, and which family therefore goes first.
"""

from intellixss.analysis.angular import (
    CHARAT_POISON,
    angular_bootable,
    angular_sandbox_escape,
    charat_payloads,
    compile_only,
    csp_blocks_inline,
    family_rank,
    mark_angular_payload,
)
from intellixss.analysis.static_dom import angular_template_finding

CDN = '<script src="//ajax.googleapis.com/ajax/libs/angularjs/1.4.0/angular.js"></script>'

NG_APP = f"<html ng-app><body>{CDN}<div>{{{{x}}}}</div></body></html>"
NG_CONTROLLER = f"<html><body>{CDN}<div ng-controller=\"c\">{{{{x}}}}</div></body></html>"
BOOTSTRAPPED = f"""
<html><body>{CDN}
<div data-ng-controller="c">{{{{x}}}}</div>
<script>angular.bootstrap(document.body, ['app']);</script>
</body></html>
"""
NO_ANGULAR = "<html><body><div>{{x}}</div></body></html>"


# --- how the page compiles ---------------------------------------------


def test_ng_app_is_a_root():
    assert angular_bootable(NG_APP) == "ng-app"


def test_ng_controller_compiles_without_ng_app():
    """``ng-controller`` hangs off a module; Angular bootstraps on its own."""
    assert angular_bootable(NG_CONTROLLER) == "ng-controller"


def test_a_script_bootstrap_needs_no_attribute_at_all():
    assert angular_bootable(BOOTSTRAPPED) == "bootstrap"


def test_a_plain_page_has_no_root():
    assert angular_bootable(NO_ANGULAR) == ""


def test_a_versioned_bundle_alone_is_not_a_compiled_document():
    """Loading Angular is not compiling: something must declare a root."""
    html = '<html><body><script src="/js/angular.min.js?v=1.5.8"></script></body></html>'
    assert angular_bootable(html) == ""


# --- CSP decides which family can fire ---------------------------------


SELF_ONLY = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}


def test_self_only_csp_forbids_eval():
    assert csp_blocks_inline("<html></html>", SELF_ONLY) is True


def test_unsafe_eval_keeps_the_function_constructor_reachable():
    headers = {"Content-Security-Policy": "script-src 'self' 'unsafe-eval'"}
    assert csp_blocks_inline("<html></html>", headers) is False


def test_no_csp_means_no_restriction():
    assert csp_blocks_inline("<html></html>", {}) is False


def test_csp_header_may_be_spelled_with_underscores():
    """aiohttp lowercases and normalises some header names."""
    headers = {"content_security_policy": "default-src 'self'"}
    assert csp_blocks_inline("<html></html>", headers) is True


# --- which escape goes first -------------------------------------------


def test_under_csp_markup_is_the_route_to_the_event_object():
    """CSP mode deletes ``Function``, so the only live escape needs markup.

    ``$event.path`` is a reference, not a call: no ``ensureSafeFunction`` check
    applies to it, and ``orderBy`` then invokes the *filter* — which the sandbox
    never inspects. A scope-assigned string can only ever be an expression, so
    this family is reachable only when the injected value becomes template
    markup.
    """
    payloads = angular_sandbox_escape(NG_APP, SELF_ONLY, markup_sink=True)
    families = {fam for _p, fam in payloads}
    assert "csp-event-object" in families
    assert families == {"csp-event-object", "expression-template"}
    first = payloads[0]
    assert "$event" in first[0] and "ng-focus" in first[0]


def test_under_csp_a_scope_string_falls_back_to_the_expression_family():
    """Nothing to place markup in: report the one thing that can still compile."""
    payloads = angular_sandbox_escape(NG_APP, SELF_ONLY)
    assert {fam for _p, fam in payloads} == {"expression-template"}


def test_without_csp_the_expression_families_come_first():
    payloads = angular_sandbox_escape(NG_APP, {})
    assert payloads[0][1] == "expression-template"
    assert any("$event" not in p for p, _f in payloads)


def test_the_charat_family_avoids_string_literals_entirely():
    """A quoting filter is exactly why the app needed this family at all."""
    for payload, family in charat_payloads():
        assert family in ("charat-overwrite", "charat-call")
        assert "'" not in payload and '"' not in payload, payload
    first = charat_payloads()[0]
    assert first[0].startswith(CHARAT_POISON)


def test_the_charat_family_uses_a_legal_lvalue():
    """``isAssignable`` accepts identifiers and member expressions only.

    The published ``[1]|orderBy:…=1`` spelling is rejected with ``$parse:lval``
    on a build that compiles the array literal first, so the lvalue here has to
    be ``toString`` — an identifier the parser already knows.
    """
    for payload, _family in charat_payloads():
        if "=1" not in payload:
            continue
        lhs = payload.split("=")[0].rsplit(";", 1)[-1]
        assert lhs.startswith("toString()"), lhs
        assert "[1]|orderBy" not in lhs, lhs


def test_family_ranking_prefers_the_expression_family():
    assert family_rank("expression-template") > family_rank("csp-event-object")
    assert family_rank("csp-event-object") > family_rank("charat-overwrite")


# --- marker binding ----------------------------------------------------


def test_marker_becomes_comma_separated_codepoints():
    out = mark_angular_payload("fromCharCode(ixCodepoints)", "ixm00ff")
    codes = ",".join(str(ord(c)) for c in "ixm00ff")
    assert out == f"fromCharCode({codes})"


def test_marker_becomes_a_statement_for_the_function_body():
    out = mark_angular_payload("constructor.constructor('ixPayload')()", "ixm00ff")
    assert out == "constructor.constructor('alert(\"ixm00ff\")')()"


def test_every_finding_candidate_is_an_expression_the_compiler_will_see():
    f = angular_template_finding("http://x.test/p", NG_CONTROLLER, marker="ixm1234abcd")
    assert f is not None
    for candidate in f.payload_candidates:
        assert candidate.startswith("{{") and candidate.endswith("}}"), candidate
        assert candidate.count("ixm1234abcd") == 1, candidate


def test_a_csp_lab_is_detected_and_says_why_no_expression_can_work():
    f = angular_template_finding(
        "http://x.test/p", NG_APP, marker="ixm1234abcd", headers=SELF_ONLY
    )
    assert f is not None
    assert "CSP forbids eval" in f.evidence


# The shape measured on the live 1.4.4 sandbox lab, verbatim.
COMPILE_ONLY = """
<script>
angular.module('labApp', []).controller('vulnCtrl',function($scope, $parse) {
    $scope.query = {};
    var key = 'search';
    $scope.query[key] = 'x';
    $scope.value = $parse(key)($scope.query);
});
</script>
<h1 ng-controller=vulnCtrl>1 search results for {{value}}</h1>
"""

EXECUTING = """
<script>
angular.module('labApp', []).controller('c', function($scope, $parse, $compile) {
    $scope.value = $parse($routeParams.q)($scope);
    $compile($scope.value)($scope);
});
</script>
"""


def test_a_compile_only_controller_is_recognised_from_its_source():
    """``$parse`` compiles; nothing calls the result or recompiles it."""
    assert compile_only(COMPILE_ONLY) is True


def test_an_app_that_runs_what_it_compiled_is_not_compile_only():
    assert compile_only(EXECUTING) is False


def test_a_page_without_parse_is_not_mistaken_for_compile_only():
    """No compiler at all is a different finding, not this one."""
    assert compile_only("<div ng-app><p>{{x}}</p></div>") is False
    assert compile_only("") is False


def test_interpolating_the_result_is_not_execution():
    """``{{value}}`` prints the compiled function; it does not run it.

    This is the exact trap the lab sets: the page looks like the value reaches
    a template, but ``{{value}}`` in an already-compiled template only prints.
    """
    assert "{{value}}" in COMPILE_ONLY
    assert compile_only(COMPILE_ONLY) is True
