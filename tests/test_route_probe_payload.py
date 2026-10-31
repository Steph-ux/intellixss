"""The payload a client route is probed with has to survive the route itself.

A hash route spends nothing on the server, but the component it lands in often
does: the tracking page asks an API for the id in its own query string, and that
API builds a server-side expression out of it. A payload carrying a single quote
ends the expression and the answer is a 500, so the sink is never rendered and an
executing route is reported clean. The marker is ours, so it is the marker that
moves to a template literal, which the expression builder accepts verbatim.
"""

from intellixss.scanner.orchestrator import route_probe_payload


def test_marker_travels_in_a_template_literal_not_a_single_quoted_string():
    payload = route_probe_payload("ixm866b973f")
    assert payload == "<img src=x onerror=alert(`ixm866b973f`)>"
    assert "'" not in payload


def test_payload_still_names_its_marker():
    """The marker has to be readable back off the dialog the payload opens."""
    assert "ixm866b973f" in route_probe_payload("ixm866b973f")
