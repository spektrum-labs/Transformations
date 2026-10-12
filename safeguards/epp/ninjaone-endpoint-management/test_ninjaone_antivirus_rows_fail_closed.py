"""NinjaOne antivirus-status checks: an error reply, a far-future timestamp and a null product field never move the answer.

Eight transforms share one set of endpoint rules (endpoint_rows). Three defects are pinned here, all synthetic:
  1. A reply that carries an error or an HTTP status of 400 or more is not a measurement even when it also
     carries product rows. It reads None (Not evaluated), never 100.
  2. One timestamp far in the future must not move the stale cutoff and drop every other device. A timestamp
     more than a day ahead is unusable; a small clock skew is still a real contact.
  3. A row with no product name, or a named product with no state, is not evidence of "no product" and not OFF.
     It is left out; if nothing readable is left the result is None, never 0. An explicit productName NONE is
     still a real answer (the device has no product).
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


def run(name, body):
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
    only = {"deviceId": 1, "definitionStatus": "Up-to-Date", "timestamp": NOW}
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
