"""Three Qualys ASM criteria answered "0" when nothing was measured, and two of them passed.

externalAssetInventoryCount read data["count"], a key the host list reply never carries, so it
answered 0 whatever the estate held. patchCompliancePercentage and meanTimeToRemediateCritical
read the detection list, which getVulnerabilities fetches with no status filter, so Qualys returns
open detections only: no Fixed detection means 0% patched and a 0-day remediation time, and 0 days
meets "lessThan 30". Each now answers None with a dataCollection error (Not evaluated) unless
the reply holds what the number is computed from. All payloads here are synthetic.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("qualys_zero_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def host_list(n, warning=None):
    response = {"DATETIME": "2026-11-19T00:00:00Z",
                "HOST_LIST": {"HOST": [{"ID": str(i), "IP": "10.0.0.%d" % i} for i in range(n)]}}
    if warning:
        response["WARNING"] = warning
    return {"HOST_LIST_OUTPUT": {"RESPONSE": response}}


def detections(*rows):
    return {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": [
        {"ID": "1", "DETECTION_LIST": {"DETECTION": list(rows)}}]}}}}


OPEN_CRITICAL = {"STATUS": "Active", "SEVERITY": "5"}
FIXED_CRITICAL = {"STATUS": "Fixed", "SEVERITY": "5", "FIRST_FOUND_DATETIME": "2026-01-01T00:00:00Z",
                  "LAST_FIXED_DATETIME": "2026-01-11T00:00:00Z"}


def answer(name, payload):
    out = load(name).transform(payload)
    key = next(iter(out["transformedResponse"]))
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]


def assert_not_measured(value, collection):
    assert value is None
    assert collection["status"] == "error" and collection["errors"]


@pytest.mark.parametrize("n", [1, 197])
def test_asset_count_is_the_number_of_hosts(n):
    value, collection = answer("externalassetinventorycount", host_list(n))
    assert value == n and collection["status"] == "success"


@pytest.mark.parametrize("response", [{"DATETIME": "x"}, {}, {"HOST_LIST": "x"}, {"HOST_LIST": {"HOST": "x"}},
                                      {"HOST_LIST": {"HOST": [1, 2]}}, {"HOST_LIST": {"HOST": []}}])
def test_no_listed_host_is_not_a_measured_zero(response):
    assert_not_measured(*answer("externalassetinventorycount", {"HOST_LIST_OUTPUT": {"RESPONSE": response}}))


def test_only_host_records_are_counted():
    payload = host_list(2)
    payload["HOST_LIST_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"] += ["junk", 3]
    assert answer("externalassetinventorycount", payload)[0] == 2


def test_a_truncated_host_list_is_not_measured():
    warning = {"CODE": "1980", "TEXT": "1000 record limit exceeded.", "URL": "https://example.invalid/?id_min=1"}
    value, collection = answer("externalassetinventorycount", host_list(1000, warning))
    assert_not_measured(value, collection)


@pytest.mark.parametrize("payload", [{}, {"count": 5}, {"HOST_LIST_OUTPUT": None}, None, "not json"])
def test_no_host_list_reply_is_not_measured(payload):
    assert_not_measured(*answer("externalassetinventorycount", payload))


def test_open_detections_only_is_not_a_patch_compliance_of_zero():
    assert_not_measured(*answer("patchcompliancepercentage", detections(OPEN_CRITICAL, OPEN_CRITICAL)))


def test_patch_compliance_is_computed_when_fixed_detections_are_present():
    value, collection = answer("patchcompliancepercentage", detections(OPEN_CRITICAL, FIXED_CRITICAL))
    assert value == "50" and collection["status"] == "success"


def test_no_remediated_critical_is_not_a_zero_day_remediation_time():
    assert_not_measured(*answer("meantimetoremediatecritical", detections(OPEN_CRITICAL)))


def test_remediation_time_is_averaged_over_fixed_criticals():
    value, collection = answer("meantimetoremediatecritical", detections(OPEN_CRITICAL, FIXED_CRITICAL))
    assert value == "10" and collection["status"] == "success"


def test_a_fix_dated_before_the_finding_is_not_a_remediation_time():
    backwards = dict(FIXED_CRITICAL, LAST_FIXED_DATETIME="2025-12-01T00:00:00Z")
    assert_not_measured(*answer("meantimetoremediatecritical", detections(backwards)))


def test_a_lowercase_fixed_status_still_counts():
    value, _ = answer("meantimetoremediatecritical", detections(dict(FIXED_CRITICAL, STATUS="FIXED")))
    assert value == "10"


@pytest.mark.parametrize("name,status", [("meantimetoremediatecritical", "Fixed"), ("criticalvulnerabilitycount", "Active")])
def test_vendor_text_does_not_reach_the_errors(name, status):
    out = load(name).transform(detections({"STATUS": status, "SEVERITY": "DO-NOT-ECHO"}))
    assert "DO-NOT-ECHO" not in str(out)


@pytest.mark.parametrize("name", ["patchcompliancepercentage", "meantimetoremediatecritical"])
def test_an_unreadable_detection_reply_is_not_measured(name):
    assert_not_measured(*answer(name, {"HOST_LIST_VM_DETECTION_OUTPUT": "garbage"}))
