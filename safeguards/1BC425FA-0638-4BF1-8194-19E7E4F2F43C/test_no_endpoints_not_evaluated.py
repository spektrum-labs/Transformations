"""Sophos MDR endpoint-list keys: an empty endpoint list is Not evaluated, never a fail.

The read returns {"items": [], "pages": {...}} when the tenant has no endpoints. There is
nothing to measure, so isBehavioralMonitoringValid, isRemovableMediaControlled and
isPatchManagementEnabled / isPatchManagementValid now read None with "no endpoints returned".
A populated list and an explicit verdict key keep their earlier readings. Synthetic bodies only.

The second half of this file covers the Sophos MDR licence read, confirmedlicensepurchased_endpoints.py:
a failed, refused, empty or partial endpoint read is Not evaluated there too, and only a complete,
readable list with no MDR endpoint is False. MDR there means the managed service only, the same rule as
mdr_transform.py: the "mtr" product or an explicit mdrManaged true, never the self-service "xdr" product.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
EMPTY = {"items": [], "pages": {"size": "500", "maxSize": "500", "nextKey": "None"}}
POPULATED = {"items": [{"id": "ep-1", "type": "computer", "health": {"overall": "good"}}],
             "pages": {"size": "500", "maxSize": "500"}}
FILES = [("isbehavioralmonitoringvalid.py", ["isBehavioralMonitoringValid"]),
         ("isremovablemediacontrolled.py", ["isRemovableMediaControlled"]),
         ("ispatchmanagementenabled.py", ["isPatchManagementEnabled", "isPatchManagementValid"])]


def run(name, body):
    spec = importlib.util.spec_from_file_location(name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


@pytest.mark.parametrize("name,keys", FILES)
@pytest.mark.parametrize("body", [EMPTY, [], {"items": []}])
def test_no_endpoints_is_not_evaluated(name, keys, body):
    out = run(name, body)
    for key in keys:
        assert out["transformedResponse"][key] is None
    assert "no endpoints returned" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name,keys", FILES)
def test_populated_list_unchanged(name, keys):
    out = run(name, POPULATED)
    for key in keys:
        assert out["transformedResponse"][key] is True


@pytest.mark.parametrize("name,keys", FILES)
def test_explicit_false_still_fails(name, keys):
    body = dict(EMPTY)
    for key in keys:
        body[key] = False
    out = run(name, body)
    for key in keys:
        assert out["transformedResponse"][key] is False


@pytest.mark.parametrize("name,keys", FILES)
def test_error_body_is_never_true(name, keys):
    out = run(name, {"error": "Unauthorized"})
    for key in keys:
        assert out["transformedResponse"][key] is not True


# ---------------------------------------------------------------------------------------------
# confirmedlicensepurchased_endpoints.py: the Sophos MDR licence read (GET /endpoint/v1/endpoints).
#
# A failed, refused, empty or partial read of the endpoint list proves nothing about the licence,
# so it is Not evaluated (None with a data-collection error), never False. False is only the
# answer to a complete, readable endpoint list in which no endpoint carries the MDR product.
# ---------------------------------------------------------------------------------------------
LICENCE_FILE = "confirmedlicensepurchased_endpoints.py"
LICENCE_KEY = "confirmedLicensePurchased"
SENTINEL = "DO-NOT-ECHO-VENDOR-TEXT"
OK_VALIDATION = {"status": "unknown", "errors": [], "warnings": []}


def licence_run(body):
    return run(LICENCE_FILE, body)


def licence_endpoint(eid, codes, **extra):
    item = {"id": eid, "type": "computer",
            "assignedProducts": [{"code": code, "status": "installed"} for code in codes]}
    item.update(extra)
    return item


def enveloped(body, validation=None):
    return {"data": body, "validation": validation or OK_VALIDATION}


class Poisoned(dict):
    """A dict whose every read raises, to drive the transform down its exception path."""

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


def assert_licence_not_evaluated(out):
    assert out["transformedResponse"] == {LICENCE_KEY: None}
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert isinstance(collection["errors"], list) and collection["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert SENTINEL not in json.dumps(out)  # the vendor's own error text is never echoed


SOPHOS_ERROR = {"error": "forbidden", "message": "Access to this tenant is not allowed " + SENTINEL,
                "correlationId": "synthetic-correlation-id", "code": "forbidden"}
MDR_PAGE = [licence_endpoint("e1", ["endpointProtection", "mtr"])]
NO_MDR_PAGE = [licence_endpoint("e1", ["endpointProtection"]), licence_endpoint("e2", ["endpointProtection", "interceptX"])]

# The four reads the house rule is about, then the rest of the ways a read can prove nothing.
UNREADABLE_BODIES = [
    ("empty endpoint list", {"items": [], "pages": {"size": "500", "maxSize": "500", "nextKey": "None"}}),
    ("empty list", []),
    ("error body", SOPHOS_ERROR),
    ("401 envelope", {"statusCode": 401, "error": "Unauthorized"}),
    ("401 status only", {"status_code": 401, "message": "Unauthorized"}),
    ("401 nested error", {"error": {"statusCode": 401, "message": "Unauthorized"}}),
    ("401 inside the data envelope", enveloped({"statusCode": 401, "message": "Unauthorized"})),
    ("403 status body", {"statusCode": 403, "message": "Forbidden " + SENTINEL}),
    ("500 status as text", {"status": "500", "message": "Internal Server Error"}),
    ("errors list", {"errors": [{"code": "forbidden", "message": SENTINEL}]}),
    ("vendor refusal marker", {"vendorErrorAsResponse": {"status": 403, "body": {"message": SENTINEL}}}),
    ("wrapped error", {"response": SOPHOS_ERROR}),
    ("enveloped error", enveloped(SOPHOS_ERROR)),
    ("enveloped empty list", enveloped([])),
    ("enveloped empty endpoint list", enveloped({"items": []})),
    ("error beside endpoints", dict(SOPHOS_ERROR, items=MDR_PAGE)),
    ("empty object", {}),
    ("none", None),
    ("empty string", ""),
    ("json null text", "null"),
    ("not json text", "Forbidden"),
    ("html text", "<html><body>Service Unavailable</body></html>"),
    ("number", 12345),
    ("missing items key", {"pages": {"size": "500", "maxSize": "500"}}),
    ("unrelated json", {"hello": "world"}),
    ("items null", {"items": None}),
    ("items not a list", {"items": "none"}),
    ("list of strings", ["error", "forbidden"]),
    ("list of error objects", [{"error": "forbidden"}]),
    ("items of error objects", {"items": [{"error": "forbidden"}]}),
    ("500 beside a response wrapper", {"statusCode": 500, "response": {"items": NO_MDR_PAGE}}),
    ("401 beside a result wrapper", {"status_code": 401, "result": {"items": NO_MDR_PAGE}}),
    ("403 as text beside an api_response wrapper", {"status": "403", "api_response": {"items": NO_MDR_PAGE}}),
    ("error beside a wrapper", {"error": "forbidden " + SENTINEL, "response": {"items": NO_MDR_PAGE}}),
    ("errors beside a wrapper", {"errors": [{"message": SENTINEL}], "Output": {"items": NO_MDR_PAGE}}),
    ("refusal marker beside a wrapper", {"vendorErrorAsResponse": {"status": 403}, "response": {"items": NO_MDR_PAGE}}),
    ("error beside a wrapper holding an MDR endpoint", {"statusCode": 500, "response": {"items": MDR_PAGE}}),
    ("500 beside a doubly wrapped list", {"statusCode": 500, "response": {"result": {"items": NO_MDR_PAGE}}}),
    ("500 on the middle of two wrappers", {"response": {"statusCode": 500, "result": {"items": NO_MDR_PAGE}}}),
    ("error on the middle of two wrappers", {"response": {"error": "forbidden " + SENTINEL, "result": {"items": NO_MDR_PAGE}}}),
    ("401 as text on the first of two wrappers", {"result": {"status": "401", "response": {"items": NO_MDR_PAGE}}}),
    ("403 on the second of three wrappers", {"response": {"result": {"statusCode": 403, "Output": {"items": NO_MDR_PAGE}}}}),
    ("failed validation", enveloped({"items": MDR_PAGE},
                                    {"status": "failed", "errors": ["body did not match the schema"], "warnings": []})),
    ("failed validation on an error body", enveloped(SOPHOS_ERROR, {"status": "failed", "errors": [], "warnings": []})),
]


@pytest.mark.parametrize("label,body", UNREADABLE_BODIES, ids=[label for label, _ in UNREADABLE_BODIES])
def test_licence_unreadable_read_is_not_evaluated(label, body):
    assert_licence_not_evaluated(licence_run(body))


def test_licence_transform_exception_is_not_evaluated():
    out = licence_run(Poisoned(items=MDR_PAGE))
    assert_licence_not_evaluated(out)
    assert out["additionalInfo"]["transformation"]["status"] == "error"  # the exception is still recorded


def test_licence_real_negative_stays_false():
    body = {"items": NO_MDR_PAGE, "pages": {"size": "500", "maxSize": "500"}}
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []
    assert "None of the 2 endpoints" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("body", [
    {"items": NO_MDR_PAGE},
    NO_MDR_PAGE,
    {"endpoints": NO_MDR_PAGE},
    enveloped({"items": NO_MDR_PAGE}),
    {"items": [licence_endpoint("e1", ["endpointProtection"], mdrManaged=False)]},
    {"items": NO_MDR_PAGE, "pages": {"size": "2", "maxSize": "500", "nextKey": "None", "total": 1}},
    {"items": NO_MDR_PAGE, "pages": {"size": "2", "total": 1, "items": 2}},
], ids=["items", "bare list", "endpoints key", "enveloped", "mdrManaged false", "stringified null cursor",
        "one page, item total matches"])
def test_licence_complete_read_with_no_mdr_endpoint_is_false(body):
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("body", [
    {"items": MDR_PAGE},
    MDR_PAGE,
    {"endpoints": MDR_PAGE},
    enveloped({"items": MDR_PAGE}),
    {"items": [licence_endpoint("e1", ["endpointProtection"], mdrManaged="true")]},
    {"items": NO_MDR_PAGE + MDR_PAGE},
], ids=["items", "bare list", "endpoints key", "enveloped", "mdrManaged true", "one MDR endpoint among others"])
def test_licence_mdr_evidence_stays_true(body):
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: True}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


# A partial read cannot prove the licence is missing: it may sit on an endpoint on a page nobody read.
PARTIAL_PAGES = [
    ("next-page cursor", {"items": NO_MDR_PAGE, "pages": {"size": "2", "maxSize": "500", "nextKey": "abc123"}}),
    ("top-level next key", {"items": NO_MDR_PAGE, "nextKey": "abc123"}),
    ("truncated flag", {"items": NO_MDR_PAGE, "truncated": True}),
    ("pages truncated", {"items": NO_MDR_PAGE, "pages": {"truncated": "true"}}),
    ("page does not start at the beginning", {"items": NO_MDR_PAGE, "pages": {"fromKey": "abc123"}}),
    ("more items than returned", {"items": NO_MDR_PAGE, "pages": {"size": "2", "items": 40, "total": 20}}),
    ("more than one page", {"items": NO_MDR_PAGE, "pages": {"size": "2", "total": 3}}),
    ("unreadable page total", {"items": NO_MDR_PAGE, "pages": {"total": "many"}}),
    ("pages not an object", {"items": NO_MDR_PAGE, "pages": "more"}),
    ("enveloped next-page cursor", enveloped({"items": NO_MDR_PAGE, "pages": {"nextKey": "abc123"}})),
]


@pytest.mark.parametrize("label,body", PARTIAL_PAGES, ids=[label for label, _ in PARTIAL_PAGES])
def test_licence_partial_read_with_no_mdr_endpoint_is_not_evaluated(label, body):
    assert_licence_not_evaluated(licence_run(body))


@pytest.mark.parametrize("label,body", [
    ("next-page cursor", {"items": MDR_PAGE, "pages": {"size": "1", "maxSize": "500", "nextKey": "abc123"}}),
    ("truncated flag", {"items": MDR_PAGE, "truncated": True}),
    ("more than one page", {"items": MDR_PAGE, "pages": {"size": "1", "total": 3}}),
], ids=["next-page cursor", "truncated flag", "more than one page"])
def test_licence_partial_read_that_shows_mdr_evidence_is_true(label, body):
    # One endpoint carrying the MDR product confirms the licence, whatever else is unread.
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: True}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_licence_full_first_page_without_a_cursor_is_not_partial():
    # A complete read of a large fleet looks like this: a full page and no cursor.
    page = [licence_endpoint("e" + str(n), ["endpointProtection"]) for n in range(500)]
    out = licence_run({"items": page, "pages": {"size": "500", "maxSize": "500"}})
    assert out["transformedResponse"] == {LICENCE_KEY: False}


@pytest.mark.parametrize("body,expected", [
    ({"statusCode": 200, "response": {"items": NO_MDR_PAGE}}, False),
    ({"status": "success", "result": {"items": NO_MDR_PAGE}}, False),
    ({"status_code": "200", "response": {"items": MDR_PAGE}}, True),
    ({"error": None, "errors": [], "response": {"items": MDR_PAGE}}, True),
    ({"status": "ok", "api_response": {"items": NO_MDR_PAGE}}, False),
    ({"response": {"statusCode": 200, "result": {"items": NO_MDR_PAGE}}}, False),
    ({"response": {"status": "ok", "result": {"items": MDR_PAGE}}}, True),
], ids=["200 beside a wrapper, no MDR", "success beside a wrapper, no MDR", "200 as text beside a wrapper, MDR",
        "empty error fields beside a wrapper, MDR", "ok beside a wrapper, no MDR",
        "200 on the middle of two wrappers, no MDR", "ok on the middle of two wrappers, MDR"])
def test_licence_ok_status_beside_a_wrapper_does_not_move(body, expected):
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: expected}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_licence_not_evaluated_reason_is_fixed_text():
    out = licence_run(SOPHOS_ERROR)
    reasons = out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["dataCollection"]["errors"]
    assert all(reason.startswith("Not evaluated") for reason in reasons)


# ---------------------------------------------------------------------------------------------
# MDR means the managed service only, the same rule as mdr_transform.py and epp_transform.py:
# the "mtr" product (Managed Threat Response) or an explicit mdrManaged true. The "xdr" product
# is the self-service XDR licence, not a managed service, so a tenant with only the XDR licence
# has no MDR licence. A failed, empty or partial read still reads None.
# ---------------------------------------------------------------------------------------------
XDR_PAGE = [licence_endpoint("e1", ["endpointProtection", "xdr"])]
MTR_AND_XDR_ONE_ENDPOINT = [licence_endpoint("e1", ["endpointProtection", "mtr", "xdr"])]
MTR_AND_XDR_TWO_ENDPOINTS = [licence_endpoint("e1", ["endpointProtection", "xdr"]),
                             licence_endpoint("e2", ["endpointProtection", "mtr"])]


@pytest.mark.parametrize("body", [
    {"items": XDR_PAGE},
    XDR_PAGE,
    {"endpoints": XDR_PAGE},
    enveloped({"items": XDR_PAGE}),
    {"response": {"items": XDR_PAGE}},
    {"items": XDR_PAGE + [licence_endpoint("e2", ["endpointProtection", "xdr"])]},
    {"items": [licence_endpoint("e1", ["xdr"], mdrManaged=False)]},
    {"items": [licence_endpoint("e1", ["xdr"], mdrManaged=None)]},
    {"items": [licence_endpoint("e1", ["xdr"], mdrManaged="false")]},
    {"items": XDR_PAGE, "pages": {"size": "1", "maxSize": "500", "nextKey": "None", "total": 1}},
], ids=["items", "bare list", "endpoints key", "enveloped", "response wrapper", "two XDR endpoints",
        "mdrManaged false", "mdrManaged null", "mdrManaged false as text", "one complete page"])
def test_licence_xdr_only_is_false(body):
    # The read succeeded and is complete; the only MDR-like evidence is the self-service XDR product.
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: False}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert "None of the" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("body", [
    {"items": [licence_endpoint("e1", ["mtr"])]},
    {"items": [licence_endpoint("e1", ["endpointProtection", "mtr"])]},
    [licence_endpoint("e1", ["endpointProtection", "interceptX", "mtr"])],
    enveloped({"items": [licence_endpoint("e1", ["endpointProtection", "mtr"])]}),
    {"result": {"items": [licence_endpoint("e1", ["endpointProtection", "mtr"])]}},
    {"items": [licence_endpoint("e1", ["endpointProtection"]), licence_endpoint("e2", ["endpointProtection", "mtr"])]},
], ids=["mtr only", "mtr with endpoint protection", "bare list", "enveloped", "result wrapper", "mtr on the second endpoint"])
def test_licence_mtr_is_true(body):
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: True}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("body", [
    {"items": MTR_AND_XDR_ONE_ENDPOINT},
    {"items": MTR_AND_XDR_TWO_ENDPOINTS},
    {"items": list(reversed(MTR_AND_XDR_TWO_ENDPOINTS))},
    enveloped({"items": MTR_AND_XDR_TWO_ENDPOINTS}),
], ids=["both on one endpoint", "both on two endpoints", "both on two endpoints, mtr first", "enveloped"])
def test_licence_mtr_and_xdr_together_is_true(body):
    out = licence_run(body)
    assert out["transformedResponse"] == {LICENCE_KEY: True}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_licence_pass_reason_counts_only_managed_endpoints():
    # One of the two endpoints carries mtr; the XDR endpoint is not part of the MDR figure.
    out = licence_run({"items": MTR_AND_XDR_TWO_ENDPOINTS})
    assert out["additionalInfo"]["transformation"]["inputSummary"]["mdrEndpoints"] == 1
    assert "1 of 2 endpoints" in out["additionalInfo"]["evaluation"]["passReasons"][0]


@pytest.mark.parametrize("flag", [True, "true", "True"])
def test_licence_xdr_with_explicit_mdr_managed_true_is_true(flag):
    # An explicit managed flag still counts, as in mdr_transform.py.
    out = licence_run({"items": [licence_endpoint("e1", ["endpointProtection", "xdr"], mdrManaged=flag)]})
    assert out["transformedResponse"] == {LICENCE_KEY: True}


XDR_ONLY_UNREADABLE = [
    ("error body beside an XDR endpoint", dict(SOPHOS_ERROR, items=XDR_PAGE)),
    ("401 body", {"statusCode": 401, "error": "Unauthorized"}),
    ("500 beside a wrapper holding an XDR endpoint", {"statusCode": 500, "response": {"items": XDR_PAGE}}),
    ("failed validation on an XDR endpoint", enveloped({"items": XDR_PAGE},
                                                        {"status": "failed", "errors": ["bad body"], "warnings": []})),
    ("empty endpoint list", {"items": []}),
    ("XDR only, next-page cursor", {"items": XDR_PAGE, "pages": {"size": "1", "maxSize": "500", "nextKey": "abc123"}}),
    ("XDR only, truncated", {"items": XDR_PAGE, "truncated": True}),
    ("XDR only, more than one page", {"items": XDR_PAGE, "pages": {"size": "1", "total": 3}}),
    ("XDR only, page does not start at the beginning", {"items": XDR_PAGE, "pages": {"fromKey": "abc123"}}),
]


@pytest.mark.parametrize("label,body", XDR_ONLY_UNREADABLE, ids=[label for label, _ in XDR_ONLY_UNREADABLE])
def test_licence_xdr_only_with_an_error_or_partial_read_is_still_not_evaluated(label, body):
    assert_licence_not_evaluated(licence_run(body))


AGREEMENT_FLEETS = [
    ("no products", [licence_endpoint("e1", [])]),
    ("endpoint protection only", [licence_endpoint("e1", ["endpointProtection"])]),
    ("mtr", [licence_endpoint("e1", ["mtr"])]),
    ("xdr", [licence_endpoint("e1", ["xdr"])]),
    ("mtr and xdr", [licence_endpoint("e1", ["mtr", "xdr"])]),
    ("xdr and mdrManaged true", [licence_endpoint("e1", ["xdr"], mdrManaged=True)]),
    ("xdr and mdrManaged false", [licence_endpoint("e1", ["xdr"], mdrManaged=False)]),
    ("mdrManaged true as text", [licence_endpoint("e1", [], mdrManaged="true")]),
    ("mdrManaged null", [licence_endpoint("e1", [], mdrManaged=None)]),
    ("mixed fleet", [licence_endpoint("e1", ["xdr"]), licence_endpoint("e2", []), licence_endpoint("e3", ["mtr"])]),
    ("xdr fleet", [licence_endpoint("e1", ["xdr"]), licence_endpoint("e2", ["xdr"])]),
]


@pytest.mark.parametrize("label,items", AGREEMENT_FLEETS, ids=[label for label, _ in AGREEMENT_FLEETS])
def test_licence_agrees_with_mdr_transform_on_what_counts_as_mdr(label, items):
    # The licence check and the MDR coverage check must not drift apart on what an MDR endpoint is.
    licence = licence_run({"items": items})["transformedResponse"][LICENCE_KEY]
    coverage = run("mdr_transform.py", {"items": items})["transformedResponse"]
    assert licence is coverage["isMDREnabled"]
