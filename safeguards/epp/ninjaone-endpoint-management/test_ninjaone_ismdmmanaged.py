"""NinjaOne isMdmManaged: True only when every mobile device is enrolled and managed, fail closed otherwise.

Fixtures are synthetic. They carry the fields the getDevicesDetailed method returns for each device (id,
organizationId, policyId, rolePolicyId, approvalStatus, offline, lastContact and created in epoch seconds,
maintenance, systemName, nodeClass, os) with made-up values.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "isMdmManaged"


def load():
    spec = importlib.util.spec_from_file_location("n1_isMdmManaged_under_test", HERE / "isMdmManaged.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


TRANSFORM = load()


def run(body):
    return TRANSFORM(body)


def value(body):
    return run(body)["transformedResponse"][KEY]


def collection(body):
    return run(body)["additionalInfo"]["dataCollection"]


def device(device_id, node_class, status="APPROVED", **over):
    record = {
        "id": device_id,
        "organizationId": 7,
        "policyId": [],
        "rolePolicyId": 30,
        "approvalStatus": status,
        "offline": False,
        "lastContact": 1760000000.0,
        "created": 1750000000.0,
        "maintenance": [],
        "systemName": "device-" + str(device_id),
        "nodeClass": node_class,
        "os": [],
    }
    record.update(over)
    return record


def phone(device_id, status="APPROVED"):
    return device(device_id, "APPLE_IOS", status)


def tablet(device_id, status="APPROVED"):
    return device(device_id, "APPLE_IPADOS", status)


def android(device_id, status="APPROVED"):
    return device(device_id, "ANDROID", status)


def mac(device_id):
    return device(device_id, "MAC", "APPROVED", policyId=100)


def windows(device_id):
    return device(device_id, "WINDOWS_WORKSTATION", "APPROVED", policyId=101)


ALL_MANAGED = [phone(1), tablet(2), android(3), mac(4), windows(5)]


def assert_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    errors = out["additionalInfo"]["dataCollection"]["errors"]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert errors and all(isinstance(e, str) and e for e in errors)


# --- measured answers ---------------------------------------------------------------------------------------

def test_every_mobile_device_approved_is_true_with_counts():
    out = run(ALL_MANAGED)
    result = out["transformedResponse"]
    assert result[KEY] is True
    assert result["totalMobileDevices"] == 3
    assert result["managedMobileDeviceCount"] == 3
    assert result["unmanagedMobileDeviceCount"] == 0
    assert result["devicesReported"] == 5
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


def test_pass_reason_carries_the_count_and_the_honesty_limit():
    reasons = run(ALL_MANAGED)["additionalInfo"]["evaluation"]["passReasons"]
    assert len(reasons) == 1
    text = reasons[0]
    assert "3 mobile devices" in text
    assert "cannot see mobile devices that are not enrolled" in text
    assert "does not prove that no unmanaged device reaches company data" in text
    assert run(ALL_MANAGED)["additionalInfo"]["evaluation"]["failReasons"] == []


def test_one_pending_mobile_device_is_a_measured_false():
    out = run([phone(1), android(2), tablet(3, "PENDING"), mac(4)])
    result = out["transformedResponse"]
    assert result[KEY] is False
    assert result["managedMobileDeviceCount"] == 2
    assert result["unmanagedMobileDeviceCount"] == 1
    assert result["totalMobileDevices"] == 3
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert "1 of 3 mobile devices" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("status", ["PENDING", "STAGED", "DECOMMISSIONED", "pending", " Staged "])
def test_a_mobile_device_that_is_not_approved_is_false(status):
    assert value([phone(1), phone(2, status)]) is False


def test_every_mobile_device_unmanaged_is_false():
    result = run([phone(1, "PENDING"), android(2, "DECOMMISSIONED")])["transformedResponse"]
    assert result[KEY] is False
    assert result["managedMobileDeviceCount"] == 0
    assert result["unmanagedMobileDeviceCount"] == 2


def test_zero_mobile_devices_is_a_measured_false():
    out = run([mac(1), windows(2)])
    result = out["transformedResponse"]
    assert result[KEY] is False
    assert result["totalMobileDevices"] == 0
    assert result["managedMobileDeviceCount"] == 0
    assert result["unmanagedMobileDeviceCount"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert "no mobile device is enrolled" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_non_mobile_device_that_is_not_approved_does_not_count():
    assert value([phone(1), device(2, "MAC", "PENDING")]) is True


def test_one_managed_mobile_device_among_a_large_fleet_is_true():
    fleet = [mac(i) for i in range(10, 40)] + [android(1)]
    assert value(fleet) is True


def test_node_class_and_status_are_read_without_case_or_space_sensitivity():
    assert value([device(1, " apple_ios ", " approved ")]) is True


# --- input shapes the neighbours accept ---------------------------------------------------------------------

@pytest.mark.parametrize("wrap", [
    lambda d: d,
    lambda d: {"data": d},
    lambda d: {"devices": d},
    lambda d: {"result": d},
    lambda d: {"results": d},
    lambda d: {"apiResponse": d},
    lambda d: {"response": {"data": d}},
    lambda d: {"data": d, "validation": {"status": "valid", "errors": [], "warnings": []}},
    lambda d: json.dumps(d),
    lambda d: json.dumps(d).encode("utf-8"),
], ids=["bare", "data", "devices", "result", "results", "apiResponse", "nested", "enriched", "json-string", "bytes"])
class TestWrappers:
    def test_true_through_the_wrapper(self, wrap):
        assert value(wrap(ALL_MANAGED)) is True

    def test_false_through_the_wrapper(self, wrap):
        assert value(wrap([phone(1), android(2, "PENDING")])) is False

    def test_zero_mobile_through_the_wrapper(self, wrap):
        assert value(wrap([mac(1)])) is False


# --- fail closed --------------------------------------------------------------------------------------------

NOT_EVALUATED = {
    "none": None,
    "empty-string": "",
    "blank-string": "   ",
    "empty-dict": {},
    "empty-list": [],
    "empty-list-json": "[]",
    "empty-bytes-list": b"[]",
    "not-json": "not json",
    "scalar-int": 5,
    "scalar-bool": True,
    "unrelated-body": {"hello": "world"},
    "unrelated-dict-with-list": {"organizations": [{"id": 1}]},
    "wrapper-with-empty-list": {"data": []},
    "wrapper-with-null-list": {"devices": None},
    "wrapper-with-dict": {"data": {"id": 1}},
    "enriched-empty": {"data": [], "validation": {"status": "unknown", "errors": [], "warnings": []}},
    "enriched-failed-empty": {"data": {}, "validation": {"status": "failed", "errors": ["schema"], "warnings": []}},
    "error-body": {"error": "invalid_token", "error_description": "Access token expired"},
    "errors-list-body": {"errors": [{"message": "boom"}]},
    "401": {"statusCode": 401, "message": "Unauthorized"},
    "403": {"statusCode": 403, "message": "Forbidden"},
    "404": {"statusCode": 404, "message": "Not Found"},
    "429": {"statusCode": 429, "message": "Too Many Requests"},
    "status-int-500": {"status": 500},
    "success-false": {"success": False, "message": "denied"},
    "error-in-wrapper": {"apiResponse": {"error": "Forbidden"}},
    "error-beside-devices": {"error": "partial", "devices": [phone(1)]},
    "pagination-incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
    "list-of-scalars": [1, "x", None],
    "list-with-a-scalar": [phone(1), 7],
    "no-node-class": [{"id": 1, "approvalStatus": "APPROVED"}, {"id": 2, "approvalStatus": "APPROVED"}],
    "one-node-class-missing": [phone(1), {"id": 2, "approvalStatus": "APPROVED"}],
    "node-class-null": [phone(1), device(2, None)],
    "node-class-number": [phone(1), device(2, 7)],
    "node-class-blank": [phone(1), device(2, "  ")],
    "mobile-without-status": [phone(1), {k: v for k, v in phone(2).items() if k != "approvalStatus"}],
    "mobile-status-null": [phone(1), device(2, "ANDROID", None)],
    "mobile-status-blank": [phone(1), device(2, "ANDROID", "")],
    "mobile-status-bool": [phone(1), device(2, "ANDROID", True)],
    "mobile-status-number": [phone(1), device(2, "ANDROID", 1)],
    "mobile-status-unknown-word": [phone(1), device(2, "ANDROID", "ENROLLED")],
    "unreadable-status-beside-a-pending-one": [phone(1, "PENDING"), device(2, "ANDROID", None)],
    "has-more-flag": {"data": ALL_MANAGED, "hasMore": True},
    "truncated-flag": {"devices": ALL_MANAGED, "truncated": True},
    "partial-flag": {"result": ALL_MANAGED, "partial": True},
    "next-page-token": {"devices": ALL_MANAGED, "nextPageToken": "abc"},
    "next-cursor": {"devices": ALL_MANAGED, "nextCursor": "abc"},
    "cursor-count-exceeds-list": {"results": ALL_MANAGED, "cursor": {"name": "c", "offset": 0, "count": 6, "expires": 0}},
    "cursor-count-bool": {"results": ALL_MANAGED, "cursor": {"count": True}},
    "cursor-count-string": {"results": ALL_MANAGED, "cursor": {"count": "5"}},
    "cursor-count-float": {"results": ALL_MANAGED, "cursor": {"count": 5.0}},
    "cursor-count-negative": {"results": ALL_MANAGED, "cursor": {"count": -1}},
    "cursor-count-null": {"results": ALL_MANAGED, "cursor": {"count": None}},
}


@pytest.mark.parametrize("body", list(NOT_EVALUATED.values()), ids=list(NOT_EVALUATED))
def test_fail_closed_is_none_with_a_reason_on_the_error_channel(body):
    assert_not_evaluated(body)


def test_a_partial_read_is_never_judged_even_when_a_pending_device_is_visible():
    body = {"devices": [phone(1, "PENDING")], "hasMore": True}
    assert_not_evaluated(body)


def test_cursor_count_equal_to_the_list_is_a_complete_read():
    body = {"results": ALL_MANAGED, "cursor": {"name": "c", "offset": 0, "count": 5, "expires": 0}}
    assert value(body) is True


def test_a_clean_continuation_marker_is_a_complete_read():
    assert value({"devices": ALL_MANAGED, "nextPageToken": "", "hasMore": False, "next": None}) is True


def test_error_bodies_never_read_true():
    for body in NOT_EVALUATED.values():
        assert value(body) is not True


def test_value_is_a_real_bool_or_none_never_a_number():
    for body in (ALL_MANAGED, [mac(1)], [phone(1, "PENDING")], None):
        assert value(body) in (True, False, None)
        assert not isinstance(value(body), int) or isinstance(value(body), bool)


def test_counts_are_whole_numbers():
    result = run([phone(1), android(2, "STAGED")])["transformedResponse"]
    for field in ("totalMobileDevices", "managedMobileDeviceCount", "unmanagedMobileDeviceCount", "devicesReported"):
        assert isinstance(result[field], int) and not isinstance(result[field], bool)


def test_response_has_the_five_sections_and_schema_version():
    out = run(ALL_MANAGED)
    assert set(out) == {"transformedResponse", "additionalInfo"}
    assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
    assert set(out["additionalInfo"]["evaluation"]) == {"passReasons", "failReasons", "recommendations", "additionalFindings"}
    assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0"
    assert out["additionalInfo"]["metadata"]["transformationId"] == KEY


def test_output_never_carries_device_names_or_ids():
    text = json.dumps(run([phone(111), android(222, "PENDING")]))
    assert "device-111" not in text
    assert "device-222" not in text


def test_the_input_is_not_modified():
    body = [phone(1), android(2, "PENDING")]
    before = json.dumps(body, sort_keys=True)
    run(body)
    assert json.dumps(body, sort_keys=True) == before
