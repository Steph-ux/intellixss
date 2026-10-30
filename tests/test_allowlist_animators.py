"""Animation handlers must be built on the element that animates.

The svg-allowlist lab permits ``<svg>`` and ``<animatetransform>`` but the
browser only fires ``onbegin`` on the animator nested *inside* its container.
Building ``<svg onbegin=...>`` produces dead code that is indistinguishable
from a blocked handler, so the lab read as CLEAN.
"""

from intellixss.models import ContextAnalysis, InjectionContext
from intellixss.scanner.orchestrator import _allowlist_payloads


def _ctx() -> ContextAnalysis:
    return ContextAnalysis(context=InjectionContext.HTML_TEXT)


def test_onbegin_nests_the_animator_in_its_container():
    payloads = _allowlist_payloads("svg", "onbegin", "ixmdeadbe", _ctx())
    assert any(
        p.startswith("<svg><animatetransform onbegin=") for p in payloads
    ), payloads


def test_onbegin_is_not_only_declared_on_the_container():
    payloads = _allowlist_payloads("svg", "onbegin", "ixmdeadbe", _ctx())
    assert not all("<animatetransform" not in p for p in payloads)


def test_ordinary_events_stay_flat():
    payloads = _allowlist_payloads("svg", "onload", "ixmdeadbe", _ctx())
    assert any(p == "<svg onload=alert('ixmdeadbe')>" for p in payloads)
    assert not any("<animatetransform" in p for p in payloads)


def test_animate_needs_a_target_attribute():
    payloads = _allowlist_payloads("svg", "onbegin", "ixmdeadbe", _ctx())
    animate = [p for p in payloads if "<animate " in p]
    assert animate and all("attributeName=" in p for p in animate), animate
