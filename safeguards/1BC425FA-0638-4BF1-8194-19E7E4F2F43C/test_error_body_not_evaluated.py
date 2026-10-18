"""An error, refusal, empty or unreadable Sophos endpoint read is Not evaluated, never False.

mdr_transform.py and epp_transform.py used to read an error body, an HTTP 4xx/5xx body, a failed
input validation, an empty {} body, a null body, an empty endpoint list and a transform that
raises as "no coverage": every verdict came back False or 0. Nothing was measured in those
cases, so every key now comes back None with additionalInfo.dataCollection.status "error" and a
non-empty errors list, which the evaluator shows as Not evaluated.

A real, successful read that proves a negative (a complete endpoint list with no managed
endpoint) still reads False / 0 as before. All payloads here are synthetic.
"""
import importlib.util
import json
import pathlib
from datetime import datetime

import pytest

HERE = pathlib.Path(__file__).parent
FILES = ["mdr_transform.py", "epp_transform.py"]
FLAG_KEY = {"mdr_transform.py": "isMDRConfigured", "epp_transform.py": "isEPPConfigured"}
# epp_transform ignores endpoints not seen recently, so build a fresh timestamp each run.
NOW = datetime.utcnow().isoformat()[:19] + "Z"
SENTINEL = "DO-NOT-ECHO-VENDOR-TEXT"
OK_VALIDATION = {"status": "unknown", "errors": [], "warnings": []}


def load(name):
    spec = importlib.util.spec_from_file_location("sophos_err_" + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(name, body):
    return load(name).transform(body)


def endpoint(eid, products, **extra):
    item = {"id": eid, "type": "computer", "lastSeenAt": NOW,
            "assignedProducts": [{"code": c, "status": "installed"} for c in products],
            "health": {"services": {"serviceDetails": []}}}
    item.update(extra)
    return item


def enveloped(body, validation=None):
    return {"data": body, "validation": validation or OK_VALIDATION}


class Poisoned(dict):
    """A dict whose every read raises, to drive a transform down its exception path."""

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


SOPHOS_ERROR = {"error": "forbidden", "message": "Access to this tenant is not allowed " + SENTINEL,
                "correlationId": "synthetic-correlation-id", "code": "forbidden"}
GATEWAY_ERROR = {"error": True, "message": "Integration execution error: HTTP 500: Server Error " + SENTINEL}

BAD_BODIES = [
    ("sophos error", SOPHOS_ERROR),
    ("gateway error flag", GATEWAY_ERROR),
    ("errors list", {"errors": [{"code": "forbidden", "message": SENTINEL}]}),
    ("403 status body", {"statusCode": 403, "message": "Forbidden " + SENTINEL}),
    ("401 status body", {"status_code": 401, "message": "Unauthorized"}),
    ("500 status body", {"status": 500, "message": "Internal Server Error"}),
    ("status code as text", {"status": "403"}),
    ("nested status error", {"error": {"statusCode": 401, "message": "Unauthorized"}}),
    ("vendor refusal marker", {"vendorErrorAsResponse": {"status": 403, "body": {"message": SENTINEL}}}),
    ("empty object", {}),
    ("empty list", []),
    ("none", None),
    ("empty string", ""),
    ("empty json object text", "{}"),
    ("json null text", "null"),
    ("not json text", "Forbidden"),
    ("json error text", json.dumps(SOPHOS_ERROR)),
    ("html text", "<html><body>Service Unavailable</body></html>"),
    ("number", 12345),
    ("missing items key", {"pages": {"size": "500", "maxSize": "500"}}),
    ("unrelated json", {"hello": "world"}),
    ("unrelated nested", {"foo": {"bar": [1, 2, 3]}}),
    ("empty endpoint list", {"items": [], "pages": {"size": "500", "maxSize": "500", "nextKey": "None"}}),
    ("empty items only", {"items": []}),
    ("items null", {"items": None}),
    ("items not a list", {"items": "none"}),
    ("list of strings", ["error", "forbidden"]),
    ("list of error objects", [{"error": "forbidden"}]),
    ("items of error objects", {"items": [{"error": "forbidden"}]}),
    ("error beside items", dict(SOPHOS_ERROR, items=[endpoint("e1", ["endpointProtection", "mtr"])])),
    ("wrapped error", {"response": SOPHOS_ERROR}),
    ("wrapped api_response error", {"api_response": {"result": GATEWAY_ERROR}}),
    ("enveloped error", enveloped(SOPHOS_ERROR)),
    ("enveloped 403", enveloped({"statusCode": 403, "message": "Forbidden"})),
    ("enveloped empty", enveloped({})),
    ("enveloped none", enveloped(None)),
    ("enveloped empty list", enveloped([])),
    ("enveloped empty endpoint list", enveloped({"items": []})),
    ("failed validation", enveloped({"items": [endpoint("e1", ["endpointProtection", "mtr"])]},
                                    {"status": "failed", "errors": ["body did not match the schema"], "warnings": []})),
    ("failed validation on an error body", enveloped(SOPHOS_ERROR, {"status": "failed", "errors": [], "warnings": []})),
]


def success_keys(name):
    """The keys a measured read returns: a not-evaluated result must carry exactly these."""
    out = run(name, {"items": [endpoint("e1", ["endpointProtection"])]})
    return set(out["transformedResponse"])


def assert_not_evaluated(name, out):
    result = out["transformedResponse"]
    assert set(result) == success_keys(name)
    assert all(value is None for value in result.values())
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert isinstance(collection["errors"], list) and collection["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert SENTINEL not in json.dumps(out)  # the vendor's own error text is never echoed


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("label,body", BAD_BODIES, ids=[label for label, _ in BAD_BODIES])
def test_bad_read_is_not_evaluated(name, label, body):
    assert_not_evaluated(name, run(name, body))


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("body", [SOPHOS_ERROR, {}, [], {"pages": {"size": "500"}}, enveloped(SOPHOS_ERROR)],
                         ids=["error", "empty object", "empty list", "missing items key", "enveloped error"])
def test_is_mdr_enabled_is_none_not_false(name, body):
    out = run(name, body)
    assert out["transformedResponse"]["isMDREnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name", FILES)
def test_bytes_body_that_is_an_error_is_not_evaluated(name):
    assert_not_evaluated(name, run(name, json.dumps(SOPHOS_ERROR).encode("utf-8")))


@pytest.mark.parametrize("name", FILES)
def test_transform_that_raises_is_not_evaluated(name):
    out = run(name, Poisoned())
    result = out["transformedResponse"]
    assert set(result) == success_keys(name)
    assert all(value is None for value in result.values())
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert out["additionalInfo"]["transformation"]["status"] == "error"


@pytest.mark.parametrize("name", FILES)
def test_not_evaluated_never_asserts_a_pass_or_a_fail(name):
    for label, body in BAD_BODIES:
        result = run(name, body)["transformedResponse"]
        for key, value in result.items():
            assert value is not True and value is not False and value != 0, (label, key)


# A real, successful read keeps its verdict, including a proven negative.

@pytest.mark.parametrize("name", FILES)
def test_complete_list_with_no_managed_endpoint_still_reads_zero(name):
    out = run(name, {"items": [endpoint("e1", ["endpointProtection"]), endpoint("e2", ["endpointProtection"], mdrManaged=False)],
                     "pages": {"size": "500", "maxSize": "500"}})
    result = out["transformedResponse"]
    assert result["MDR"] == 0
    assert result["isMDREnabled"] is False
    assert result["isMDRLoggingEnabled"] is False
    assert result["isEPPEnabled"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("wrap", [lambda body: body, enveloped, lambda body: {"response": body}],
                         ids=["plain", "enveloped", "wrapped"])
def test_proven_negative_reads_false_in_every_wrapper(name, wrap):
    body = {"items": [endpoint("e1", ["endpointProtection"])]}
    out = run(name, wrap(body))
    assert out["transformedResponse"]["isMDREnabled"] is False
    assert out["transformedResponse"]["MDR"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", FILES)
def test_bare_list_with_no_managed_endpoint_still_reads_zero(name):
    out = run(name, [endpoint("e1", ["endpointProtection"])])
    assert out["transformedResponse"]["isMDREnabled"] is False
    assert out["transformedResponse"]["MDR"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", FILES)
def test_managed_endpoint_still_reads_true(name):
    out = run(name, enveloped({"items": [endpoint("e1", ["endpointProtection", "mtr"])]}))
    assert out["transformedResponse"]["isMDREnabled"] is True
    assert out["transformedResponse"]["MDR"] == 100
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", FILES)
def test_empty_error_fields_beside_a_real_list_do_not_block_a_read(name):
    body = {"items": [endpoint("e1", ["endpointProtection", "mtr"])], "error": None, "errors": [], "status": 200}
    out = run(name, body)
    assert out["transformedResponse"]["isMDREnabled"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("flag", [True, False])
def test_a_configured_flag_beside_a_complete_list_is_ignored(name, flag):
    """The configured key is derived from the endpoint list alone, so a flag in the body changes nothing."""
    items = [endpoint("e1", ["endpointProtection"])]
    plain = run(name, {"items": items})
    flagged = run(name, {"items": items, FLAG_KEY[name]: flag})
    assert flagged["transformedResponse"] == plain["transformedResponse"]
    assert flagged["additionalInfo"]["dataCollection"]["status"] == "success"


def test_dark_fleet_of_stale_endpoints_still_reads_false():
    """epp_transform: a complete list whose every endpoint is stale is a measured negative, not an empty read."""
    old = "2020-01-01T00:00:00Z"
    out = run("epp_transform.py", {"items": [endpoint("e1", ["endpointProtection", "mtr"], lastSeenAt=old)]})
    assert out["transformedResponse"]["isEPPEnabled"] is False
    assert out["transformedResponse"]["isMDREnabled"] is False
    assert out["transformedResponse"]["staleEndpointCount"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    # A None criterion beside a success status is graded as a failure, so a measured negative carries no None:
    # with no active endpoint there is no protected endpoint, so configured is False and misconfigured is True.
    assert out["transformedResponse"]["isEPPConfigured"] is False
    assert out["transformedResponse"]["isEPPMisconfigured"] is True
    assert [key for key, value in out["transformedResponse"].items() if value is None] == []
