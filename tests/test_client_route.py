"""Client-side routes: a parameter the router reads is a target too.

A hash-routed single-page application never sends its route to the server, so
nothing in the document or the query string describes it. The only evidence is
the bundle: the component reads ``route.snapshot.queryParams.q`` and the search
box navigates to ``/search`` with ``{queryParams:{q:…}}``. Juice Shop's
documented DOM XSS lives exactly there — ``q`` reaches
``bypassSecurityTrustHtml`` and lands in ``[innerHTML]`` — and a discovery pass
that only looks at ``location.search`` reports the page as clean.
"""

from intellixss.discovery.targets import detect_client_route_params
from intellixss.http.client import set_hash_query_param

# The shapes are taken verbatim from the Juice Shop 20.3.0 bundle.
JUICE_SEARCH = (
    "filterTable(){let t=this.route.snapshot.queryParams.q;"
    "t?(t=t.trim(),this.searchValue=this.sanitizer.bypassSecurityTrustHtml(t)):0}"
)
JUICE_NAVIGATE = (
    "search(t){if(t){let i={queryParams:{q:t}};"
    "this.ngZone.run(()=>this.router.navigate([`/search`],i))}"
    "else this.router.navigate([`/search`])}"
)
JUICE_HASH = "RouterModule.forRoot(routes,{useHash:!0})"


def test_navigate_call_pairs_the_route_with_its_query_key():
    """``navigate(['/search'], {queryParams:{q:t}})`` names both halves."""
    assert ("/search", "q") in detect_client_route_params(JUICE_NAVIGATE)


def test_snapshot_query_param_is_read_without_a_route():
    """The reader is in a different method than the writer — that is the point.

    ``filterTable`` only proves the key exists; the route comes from the call
    that navigates to it. Discovery must collect the key even when the reader
    sits alone in its own method.
    """
    assert ("", "q") in detect_client_route_params(JUICE_SEARCH)


def test_query_param_map_get_names_its_key():
    js = "let n=this.route.snapshot.queryParamMap.get(`redirectUrl`)??`/search`"
    assert ("", "redirectUrl") in detect_client_route_params(js)


def test_a_key_read_through_a_local_object_is_not_invented():
    """``queryParams[k]`` names nothing; only literals are actionable."""
    assert detect_client_route_params("let t=this.route.snapshot.queryParams[k]") == []


# The writer shape of the built Angular bundle, verbatim from Juice Shop 20.3.0.
# The navigate call sits just past the 400 characters that used to be searched
# around the object, so a window measured from the object's ``{`` never sees it
# while a window measured from its ``}`` already did. These strings are edited
# to keep that distance; the constant is deliberately not tuned to them.
JUICE_TRACK_ORDER = (
    "openConfirmationPDF(t){let i=`${this.basketService.hostServer}/ftp/order_${t}.pdf`;"
    "window.open(i,`_blank`)}trackOrder(t){this.ngZone.run(()=>L$1(this,null,function*(){"
    "let i={queryParams:{id:t}};"
    # The build inlines the component body between the local and the call.
    "const " + "s" * 480 + "=1;"
    "return yield this.router.navigate([`/track-result`],i)}))}"
    "static ɵfac=function(i){return new(i||e)}"
)



def test_navigate_call_pairs_the_route_across_a_function_boundary():
    """The built form hoists the object into a local before the navigate call.

    ``trackOrder(t){… let i={queryParams:{id:t}}; … navigate([`/track-result`],i)}``
    read as an empty route probes ``/`` instead of ``#/track-result``, and the
    sink is never visited. The route must follow the call, however far the
    object sits from it.
    """
    pairs = detect_client_route_params(JUICE_TRACK_ORDER)
    assert ("/track-result", "id") in pairs
    # The empty-route reading would have the scanner probe ``/?id=`` forever.
    assert ("", "id") not in pairs


def test_the_nearest_navigate_after_the_object_wins():
    """Two writers in one bundle pair with their own routes, in order.

    A bundle carries the search box and the order-history link side by side;
    pairing the first object with the second route sends the payload to the
    wrong component and the scan reports a clean page.
    """
    js = (
        "search(t){let i={queryParams:{q:t}};this.router.navigate([`/search`],i)}"
        "trackOrder(t){let i={queryParams:{id:t}};this.router.navigate([`/track-result`],i)}"
    )
    pairs = detect_client_route_params(js)
    assert ("/search", "q") in pairs
    assert ("/track-result", "id") in pairs


def test_hash_route_injection_lands_inside_the_fragment():
    """The payload has to travel in the fragment, not the query string.

    ``http://host/#/search?q=…`` is one URL; the server only ever sees ``/``.
    Writing the value into the real query string produces ``/?q=…``, which the
    router never reads and the browser confirmation then reports as clean.
    """
    url = set_hash_query_param(
        "https://t.test/#/search", "q", "<img src=x onerror=alert(1)>"
    )
    assert url == "https://t.test/#/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"


def test_hash_route_injection_replaces_an_existing_value():
    url = set_hash_query_param("https://t.test/#/search?q=old&lang=en", "q", "new")
    assert url == "https://t.test/#/search?q=new&lang=en"
