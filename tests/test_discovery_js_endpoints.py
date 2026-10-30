"""Discovery of JSON endpoints: a request the bundle builds is a target.

A single-page application ships no form and no endpoint in its markup. The
only evidence of what it writes is the call its bundle makes — Angular's
``this.http.put(url, body)``, the older ``$.post``, a ``fetch`` with a method.
Reading only the document found one target on Juice Shop and missed the stored
review sink entirely.
"""

from intellixss.discovery.targets import (
    API_BODY_FIELDS,
    detect_js_endpoints,
    discover_js_endpoints,
)

BASE = "http://127.0.0.1:3000/"


def test_angular_put_with_literal_path_is_a_put_target():
    """``http.put(`${host}/rest/products/${id}/reviews`, body)`` stores."""
    js = (
        "createReview(t,i){return this.http.put(`/rest/products/${t}/reviews`,"
        "{message:i.message,author:i.author})}"
    )
    endpoints = detect_js_endpoints(js, BASE)
    assert ("PUT", BASE + "rest/products/:id/reviews", "message") in endpoints


def test_api_post_names_the_body_field_it_writes():
    """``http.post('/api/Complaints', {message: t})`` names ``message``."""
    js = "this.success=this.http.post('/api/Complaints',{message:this.message,InvoiceId:1})"
    endpoints = detect_js_endpoints(js, BASE)
    assert ("POST", BASE + "api/Complaints", "message") in endpoints


def test_wrapper_call_without_a_body_field_is_not_invented():
    """``addFeedback(t)`` sending its argument hides the field name.

    The endpoint is still worth a try, but no body field is attributed to it:
    guessing one sends a value the handler never reads, and the benched result
    then blames the scanner for the guess.
    """
    js = "addFeedback(t){return this.http.post('/api/Feedbacks',t)}"
    endpoints = detect_js_endpoints(js, BASE)
    assert ("POST", BASE + "api/Feedbacks") in endpoints


def test_jquery_post_keeps_its_field():
    js = "$.post('/api/Feedbacks',{comment:c,rating:1})"
    assert ("POST", BASE + "api/Feedbacks", "comment") in detect_js_endpoints(js, BASE)


def test_fetch_with_method_is_a_post_target():
    js = "fetch('/api/Users',{method:'POST',body:JSON.stringify({email:e})})"
    assert ("POST", BASE + "api/Users", "email") in detect_js_endpoints(js, BASE)


def test_get_endpoints_keep_the_old_shape():
    """The tuple surface of ``discover_js_endpoints`` does not change."""
    js = "fetch('/rest/products/search?q=x')"
    assert discover_js_endpoints(js, BASE) == [BASE + "rest/products/search?q=x"]


def test_relative_and_absolute_urls_resolve_against_the_page():
    js = "http.post('/api/Feedbacks',{comment:c});http.post('api/Feedbacks',{comment:c})"
    assert detect_js_endpoints(js, BASE) == [("POST", BASE + "api/Feedbacks", "comment")]


def test_template_interpolation_becomes_a_path_parameter():
    js = "http.put(`/rest/products/${id}/reviews`,{message:m})"
    endpoints = detect_js_endpoints(js, BASE)
    assert endpoints[0][0] == "PUT"
    assert endpoints[0][1].endswith("/rest/products/:id/reviews")


def test_api_body_fields_cover_the_common_names():
    for name in ("q", "message", "comment", "content", "text", "name"):
        assert name in API_BODY_FIELDS


def test_service_base_is_resolved_from_the_field_the_module_builds():
    """``host=this.hostServer+`/rest/products``` then ``${this.host}/${id}/reviews``.

    The field holds the prefix and the call holds the suffix. Reading the
    template literally made the prefix a route parameter, so the endpoint came
    out as ``/:id/:id/reviews`` and every product review sink was lost.
    """
    js = (
        "host=this.hostServer+`/rest/products`;"
        "create(t,i){return this.http.put(`${this.host}/${t}/reviews`,{message:i.message})}"
    )
    endpoints = detect_js_endpoints(js, BASE)
    assert ("PUT", BASE + "rest/products/:id/reviews", "message") in endpoints


def test_a_path_segment_and_a_field_can_share_a_letter():
    """``/rest/products/search?q=`` is not a template interpolation.

    ``q`` is both a query parameter name and, in another call, a minified
    body key. Only ``${…}`` is a route parameter; a plain ``q`` in a query
    string is part of the path.
    """
    js = (
        "hostServer=F$.hostServer;"
        "this.http.get(`${this.hostServer}/rest/products/search?q=${t}`)"
    )
    endpoints = discover_js_endpoints(js, BASE)
    assert endpoints == [BASE + "rest/products/search?q=:id"]


def test_minified_body_keys_are_read_in_order():
    """A minified body is ``{q:n.query,a:i}`` — the first key is the field.

    Reading the *value* instead of the key named the minified local, and the
    scanner then injected into a field the handler never read.
    """
    js = "search(n,i){return this.http.post(`/rest/products/${n}/reviews`,{q:n.query,a:i})}"
    endpoints = detect_js_endpoints(js, BASE)
    assert ("POST", BASE + "rest/products/:id/reviews", "q") in endpoints
    assert not any(len(e) > 2 and e[2] == "n" for e in endpoints)


def test_env_object_member_is_the_site_root():
    """``${F$.hostServer}/rest/2fa/setup`` — a dotted origin reference.

    The app config object is captured directly in some classes instead of
    being copied onto the instance, so the field has no declaration to find;
    the member name itself says it is the origin.
    """
    js = "setup(t){return this.http.post(`${F$.hostServer}/rest/2fa/setup`,{password:t})}"
    assert ("POST", BASE + "rest/2fa/setup", "password") in detect_js_endpoints(js, BASE)


def test_trailing_slash_is_the_same_route():
    """``this.host+`/` `` ends on a slash; the endpoint does not."""
    js = (
        "host=this.hostServer+`/api/Complaints`;"
        "save(t){return this.http.post(this.host+`/`,{message:t.message})}"
    )
    assert ("POST", BASE + "api/Complaints", "message") in detect_js_endpoints(js, BASE)
    assert not any(e[1].endswith("Complaints/") for e in detect_js_endpoints(js, BASE))

    """Each minified service declares its own ``host``.

    A single name→prefix map for the whole bundle let the last service win, so
    a review call was resolved against the complaint service's ``/api``
    prefix and pointed at an endpoint that does not exist.
    """
    js = (
        "class e{http=h;hostServer=o.hostServer;host=this.hostServer+`/rest/products`;"
        "create(t,i){return this.http.put(`${this.host}/${t}/reviews`,{message:i.message})}}\n"
        "class s{http=h;hostServer=o.hostServer;host=this.hostServer+`/api/Complaints`;"
        "save(t){return this.http.post(this.host+`/`,{message:t.message})}}\n"
    )
    endpoints = detect_js_endpoints(js, BASE)
    assert ("PUT", BASE + "rest/products/:id/reviews", "message") in endpoints
    assert ("POST", BASE + "api/Complaints", "message") in endpoints
    assert not any("rest/products" in e[1] and e[0] != "PUT" for e in endpoints)


def test_record_built_into_a_local_is_read_from_the_component():
    """``let i={message:t.value,author:this.author}`` then ``create(id,i)``.

    The service takes the ready-made record and only forwards it, so the field
    names live in the component beside it. That component is the same module,
    one class away — the review form on Juice Shop.
    """
    js = (
        "class e{hostServer=o.hostServer;host=this.hostServer+`/rest/products`;"
        "create(t,i){return this.http.put(`${this.host}/${t}/reviews`,i)}}\n"
        "class d{productReviewService=p$1(mo);addReview(t){"
        "let i={message:t.value,author:this.author};t.value=``,"
        "this.productReviewService.create(this.data.productData.id,i)}}\n"
    )
    endpoints = detect_js_endpoints(js, BASE)
    assert ("PUT", BASE + "rest/products/:id/reviews", "message") in endpoints
    # ``author`` is copied from the session, not typed: it is not a sink.
    assert not any(len(e) > 2 and e[2] == "author" for e in endpoints)


def test_record_grown_through_comma_chained_assignments():
    """``this.complaint={},this.complaint.UserId=t.id,this.complaint.message=…``.

    Minified Angular chains assignments through one comma expression. Reading a
    value up to the next semicolon swallowed the whole chain into ``UserId``, so
    the complaint sink named a handle instead of the message.
    """
    js = (
        "class e{hostServer=o.hostServer;host=this.hostServer+`/api/Complaints`;"
        "save(t){return this.http.post(this.host+`/`,t)}}\n"
        "class c{complaintService=p$1(Bs);messageControl=new _d(``);saveComplaint(){"
        "this.complaint={},this.complaint.UserId=u.id,"
        "this.complaint.message=this.messageControl.value,"
        "this.complaintService.save(this.complaint)}}\n"
    )
    endpoints = detect_js_endpoints(js, BASE)
    assert ("POST", BASE + "api/Complaints", "message") in endpoints
    assert not any(len(e) > 2 and e[2] == "UserId" for e in endpoints)


def test_reactive_form_value_is_user_text():
    """``form.value.comment`` is what the feedback form holds.

    A reactive form's record is read in one expression rather than assigned
    field by field, and the read ends in ``.value``; without that the feedback
    sink was the only JSON write on the bundle left unnamed.
    """
    js = (
        "class e{hostServer=o.hostServer;host=this.hostServer+`/api/Feedbacks`;"
        "save(a){return this.http.post(this.host+`/`,a)}}\n"
        "class f{feedbackService=p$1(S);form=new Y();save(){"
        "this.feedbackService.save({comment:this.form.value.comment,rating:3})}}\n"
    )
    assert ("POST", BASE + "api/Feedbacks", "comment") in detect_js_endpoints(js, BASE)
