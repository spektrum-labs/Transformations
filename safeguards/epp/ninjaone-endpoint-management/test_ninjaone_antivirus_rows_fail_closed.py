"""NinjaOne antivirus-status checks: an error reply, a far-future timestamp, a null product field and an empty reply never move the answer.

Eight transforms share one set of endpoint rules (endpoint_rows). Four defects are pinned here, all synthetic:
  1. A reply that carries an error or an HTTP status of 400 or more is not a measurement even when it also
     carries product rows. It reads None (Not evaluated), never 100.
  2. One timestamp far in the future must not move the stale cutoff and drop every other device. A timestamp
     more than a day ahead is unusable; a small clock skew is still a real contact.
  3. A row with no product name, or a named product with no state, is not evidence of "no product" and not OFF.
     It is left out; if nothing readable is left the result is None, never 0. An explicit productName NONE is
     still a real answer (the device has no product). The signature check also reads a row that carries a
     definitionStatus even when the product name is missing.
  4. An empty reply (no rows, or no row with a device id) proves nothing: None, never False or 0.
"""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent

FILES = [
    "endpointOperationalStatusUnprotectedCount",
    "isEDRDeployed",
    "isEPPConfigured",
    "isEPPDeployed",
    "isEPPEnabled",
    "isEPPMisconfigured",
    "isSignatureUpToDate",
    "requiredCoveragePercentage",
]
# Files that read productState; isSignatureUpToDate reads definitionStatus and does not need the state.
STATE_FILES = [f for f in FILES if f != "isSignatureUpToDate"]

NOW = time.time()
DAY = 86400.0


def load(name):
    spec = importlib.util.spec_from_file_location("nj_rows_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def with_roster(body):
    """isEPPConfigured measures against the device list beside the report, so a report sent to it carries one.

    The roster is exactly the devices the rows mention, so nothing is missing from the report and the other
    rules under test are the only thing that moves the answer. Bodies that already carry a list are unchanged.
    """
    if not isinstance(body, dict):
        return body
    out = dict(body)
    if isinstance(out.get("results"), list) and "devices" not in out:
        ids = []
        for r in out["results"]:
            if isinstance(r, dict) and r.get("deviceId") is not None and r.get("deviceId") not in ids:
                ids.append(r.get("deviceId"))
        out["devices"] = [{"id": i, "nodeClass": "WINDOWS_WORKSTATION", "lastContact": NOW} for i in ids]
    for key, inner in list(out.items()):
        if isinstance(inner, dict) and key != "devices":
            out[key] = with_roster(inner)
    return out


def run(name, body):
    if name == "isEPPConfigured":
        body = with_roster(body)
    return load(name)(body)


def value(name, out):
    return out["transformedResponse"][name]


def not_evaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


def row(did, product="Defender", state="ON", seen=None, definition="Up-to-Date"):
    return {"deviceId": did, "productName": product, "productState": state,
            "definitionStatus": definition, "timestamp": NOW if seen is None else seen}


def good_rows(n=3):
    return [row(i + 1) for i in range(n)]


@pytest.mark.parametrize("name", FILES)
def test_a_clean_reply_is_measured(name):
    out = run(name, {"results": good_rows()})
    assert value(name, out) is not None
    assert not not_evaluated(out)


# 1. error bodies, with and without rows
ERROR_FIELDS = [
    {"error": "Forbidden"},
    {"errors": ["Forbidden"]},
    {"error": {"message": "no access"}},
    {"status": 403},
    {"statusCode": 403, "message": "Forbidden"},
    {"status_code": 500},
]


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("extra", ERROR_FIELDS)
def test_error_field_beside_on_rows_is_not_evaluated(name, extra):
    body = dict(extra, results=good_rows())
    out = run(name, body)
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("extra", ERROR_FIELDS)
def test_error_field_beside_on_rows_inside_a_wrapper_is_not_evaluated(name, extra):
    body = {"apiResponse": dict(extra, results=good_rows())}
    out = run(name, body)
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
def test_empty_error_fields_are_not_errors(name):
    body = {"results": good_rows(), "error": None, "errors": [], "status": 200}
    out = run(name, body)
    assert value(name, out) is not None
    assert not not_evaluated(out)


# 2. one far-future timestamp
@pytest.mark.parametrize("name", FILES)
def test_one_far_future_timestamp_does_not_drop_the_other_devices(name):
    rows = [row(1, seen=NOW + 400 * DAY), row(2), row(3)]
    out = run(name, {"results": rows})
    scope = out["transformedResponse"]
    # Devices 2 and 3 stay judged; only the device with the impossible timestamp is left out.
    assert scope["devicesLeftOutStale"] == 1
    assert scope["devicesJudged"] == 2
    assert value(name, out) is not None


@pytest.mark.parametrize("name", FILES)
def test_small_clock_skew_is_still_a_real_contact(name):
    rows = [row(1, seen=NOW + 6 * 3600), row(2), row(3)]
    out = run(name, {"results": rows})
    scope = out["transformedResponse"]
    assert scope["devicesLeftOutStale"] == 0
    assert scope["devicesJudged"] == 3


@pytest.mark.parametrize("name", FILES)
def test_more_than_a_day_ahead_is_unusable(name):
    rows = [row(1, seen=NOW + 2 * DAY), row(2), row(3)]
    out = run(name, {"results": rows})
    scope = out["transformedResponse"]
    assert scope["devicesLeftOutStale"] == 1
    assert scope["devicesJudged"] == 2


@pytest.mark.parametrize("name", FILES)
def test_a_future_timestamp_cannot_hide_a_dark_fleet(name):
    old = NOW - 40 * DAY
    rows = [row(1, seen=NOW + 400 * DAY), row(2, seen=old), row(3, seen=old)]
    out = run(name, {"results": rows})
    assert value(name, out) is None
    assert not_evaluated(out)


# 3. null product name or state
@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("bad", [
    {"productName": None, "productState": None},
    {"productName": None, "productState": "ON"},
    {"productName": "", "productState": "ON"},
    {"productState": "ON"},
])
def test_a_row_with_no_product_name_is_not_evidence(name, bad):
    # No definitionStatus either: a row that carries one is evidence for the signature check (see below).
    only = {"deviceId": 1, "timestamp": NOW}
    only.update(bad)
    out = run(name, {"results": [only]})
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", STATE_FILES)
@pytest.mark.parametrize("state", [None, "", "  "])
def test_a_named_product_with_no_state_reads_none_not_zero(name, state):
    out = run(name, {"results": [row(1, state=state)]})
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", STATE_FILES)
def test_unreadable_rows_are_left_out_and_counted(name):
    rows = [row(1), row(2), row(3, state=None), {"deviceId": 4, "productName": None, "productState": None, "timestamp": NOW}]
    out = run(name, {"results": rows})
    scope = out["transformedResponse"]
    assert scope["devicesLeftOutUnreadable"] == 2
    assert scope["devicesJudged"] == 2
    assert value(name, out) is not None


def test_signature_check_does_not_need_the_product_state():
    out = run("isSignatureUpToDate", {"results": [row(1, state=None), row(2, state=None)]})
    assert value("isSignatureUpToDate", out) is not None
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", ["isEPPConfigured", "requiredCoveragePercentage"])
def test_explicit_product_none_is_still_an_unprotected_device(name):
    rows = [{"deviceId": 1, "productName": "NONE", "timestamp": NOW}, row(2)]
    out = run(name, {"results": rows})
    assert value(name, out) == 50
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", ["isEPPConfigured", "requiredCoveragePercentage"])
def test_percentage_counts_only_readable_devices(name):
    rows = [row(1), row(2, state="OFF"), row(3, state=None)]
    out = run(name, {"results": rows})
    assert value(name, out) == 50


# 4. an empty reply proves nothing
EMPTY_BODIES = [
    {},
    [],
    {"results": []},
    {"data": []},
    {"results": [{"productName": "Defender", "productState": "ON", "definitionStatus": "Up-to-Date", "timestamp": NOW}]},
]


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("body", EMPTY_BODIES)
def test_an_empty_reply_is_not_evaluated(name, body):
    # No device id anywhere, or no rows at all: nothing to judge. Never False, never 0, never a pass.
    out = run(name, body)
    assert value(name, out) is None
    assert not_evaluated(out)


# 5. signature currency reads definitionStatus, so a row that carries one is evidence even without a product name
def null_name_row(did, definition, state=None):
    return {"deviceId": did, "productName": None, "productState": state, "definitionStatus": definition, "timestamp": NOW}


def test_a_null_name_out_of_date_row_still_fails_signatures():
    out = run("isSignatureUpToDate", {"results": [row(1), null_name_row(2, "Out-of-Date")]})
    assert value("isSignatureUpToDate", out) is False
    assert out["transformedResponse"]["outOfDateCount"] == 1
    assert out["transformedResponse"]["devicesLeftOutUnreadable"] == 0


def test_a_null_name_up_to_date_row_counts_for_signatures():
    out = run("isSignatureUpToDate", {"results": [null_name_row(1, "Up-to-Date"), row(2)]})
    assert value("isSignatureUpToDate", out) is True
    assert out["transformedResponse"]["devicesJudged"] == 2


def test_a_null_name_row_with_no_definition_status_is_left_out_of_signatures():
    out = run("isSignatureUpToDate", {"results": [row(1), {"deviceId": 2, "productName": None, "timestamp": NOW}]})
    assert out["transformedResponse"]["devicesLeftOutUnreadable"] == 1
    assert out["transformedResponse"]["devicesJudged"] == 1
    assert value("isSignatureUpToDate", out) is True
