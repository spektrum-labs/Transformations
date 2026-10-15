"""NinjaOne isEPPConfigured counts endpoint protection only from a real antivirus or EPP product state per device.

A policy id says which NinjaOne policy a device uses, not that a protection product is installed or
running. So the device list alone (policyId set, policyId empty because the policy is inherited from the
role, or anything else) never reads positive and never reads as a fail: with no product data the check is
not evaluated (None). With the antivirus-status report the value is the whole-number percentage of judged
devices that have a product reporting ON. Synthetic data only."""
import importlib.util
import json
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location("ninja_epp_configured", HERE / "isEPPConfigured.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def run(body):
    return load()(body)


NOW = time.time()


def device(did, policy=None, role_policy=101, node_class="WINDOWS_WORKSTATION", seen=None):
    return {"id": did, "organizationId": 10, "nodeClass": node_class, "policyId": policy,
            "rolePolicyId": role_policy, "lastContact": NOW if seen is None else seen}


def av_row(did, product="Defender", state="ON", seen=None):
    return {"deviceId": did, "productName": product, "productState": state,
            "timestamp": NOW if seen is None else seen}


def report(rows, devices="roster"):
    """A report body. By default the device list holds exactly the devices the rows mention (a complete roster);
    pass devices=None for a body with no device list at all, or any other value to send that as the list."""
    body = {"results": rows}
    if isinstance(devices, str) and devices == "roster":
        ids = []
        for r in rows:
            if isinstance(r, dict) and r.get("deviceId") is not None and r.get("deviceId") not in ids:
                ids.append(r.get("deviceId"))
        devices = [device(i) for i in ids]
    if devices is not None:
        body["devices"] = devices
    return body


def value(out):
    return out["transformedResponse"]["isEPPConfigured"]


def fleet_of(n):
    return [device(i + 1) for i in range(n)]


def not_evaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


class TestDeviceListAloneIsNotEvidence:
    def test_policy_set_on_every_device_is_never_positive(self):
        out = run([device(1, policy=100), device(2, policy=100), device(3, policy=[100])])
        assert value(out) is None
        assert not_evaluated(out)

    def test_inherited_policy_empty_policy_id_is_not_a_fail(self):
        out = run([device(1, policy=None), device(2, policy=[]), device(3, policy="")])
        assert value(out) is None
        assert not_evaluated(out)

    def test_mixed_policy_assignment_is_not_a_number(self):
        out = run({"data": [device(1, policy=100), device(2, policy=None)]})
        assert value(out) is None

    @pytest.mark.parametrize("body", [{}, [], {"data": []}, {"results": []}, None, "{}",
                                      {"error": "Unauthorized"}, {"statusCode": 401, "error": "Unauthorized"}])
    def test_no_data_is_not_evaluated(self, body):
        out = run(body)
        assert value(out) is None
        assert not_evaluated(out)


class TestProductStateIsTheEvidence:
    def test_percentage_counts_devices_with_a_running_product(self):
        rows = [av_row(1), av_row(2), av_row(3, product="NONE", state=None)]
        out = run(report(rows))
        assert value(out) == 66

    def test_every_device_protected_reads_one_hundred(self):
        assert value(run(report([av_row(1), av_row(2)]))) == 100

    def test_empty_policy_id_does_not_lower_the_result(self):
        devices = [device(1, policy=None), device(2, policy=None)]
        assert value(run(report([av_row(1), av_row(2)], devices))) == 100

    def test_policy_id_does_not_rescue_a_device_with_no_product(self):
        devices = [device(1, policy=100), device(2, policy=100)]
        rows = [av_row(1, product="NONE", state=None), av_row(2, product="NONE", state=None)]
        out = run(report(rows, devices))
        assert value(out) == 0

    @pytest.mark.parametrize("state", ["OFF", "EXPIRED", "SNOOZED", "UNKNOWN"])
    def test_a_product_that_is_not_running_is_not_counted(self, state):
        out = run(report([av_row(1, state=state), av_row(2)]))
        assert value(out) == 50

    @pytest.mark.parametrize("state", [None, ""])
    def test_a_named_product_with_no_state_is_left_out_not_counted_off(self, state):
        # No state is not "off": the row is unreadable and the device is not judged (see test_ninjaone_antivirus_rows_fail_closed).
        out = run(report([av_row(1, state=state), av_row(2)]))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesLeftOutUnreadable"] == 1

    def test_one_running_product_among_several_counts_the_device_once(self):
        rows = [av_row(1, product="Defender", state="OFF"), av_row(1, product="Other AV", state="ON"), av_row(2)]
        assert value(run(report(rows))) == 100

    def test_stale_devices_are_left_out(self):
        old = NOW - 40 * 86400
        rows = [av_row(1), av_row(2, seen=old), av_row(3, product="NONE", state=None, seen=old)]
        out = run(report(rows))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesLeftOutStale"] == 2

    def test_phones_and_tablets_are_left_out(self):
        devices = [device(1), device(2, node_class="APPLE_IOS")]
        rows = [av_row(1), av_row(2, product="NONE", state=None)]
        out = run(report(rows, devices))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesLeftOutMobile"] == 1

    def test_every_device_left_out_is_not_evaluated(self):
        old = NOW - 60 * 86400
        out = run(report([av_row(1, seen=old), av_row(2, seen=old)]))
        assert value(out) is None
        assert not_evaluated(out)

    def test_error_body_is_never_positive(self):
        out = run({"results": [], "error": "Unauthorized"})
        assert value(out) is None


class TestDevicesMissingFromTheReportCountAgainst:
    """A device in the device list that the antivirus-status report does not mention is not shown protected.

    It counts in the denominator and never in the numerator (missing is never a pass)."""

    def fleet(self, n):
        return [device(i + 1) for i in range(n)]

    def test_two_running_of_ten_devices_reads_twenty(self):
        out = run(report([av_row(1), av_row(2)], self.fleet(10)))
        assert value(out) == 20
        scope = out["transformedResponse"]
        assert scope["totalDevices"] == 10
        assert scope["devicesWithRunningProduct"] == 2
        assert scope["devicesNotInReport"] == 8

    def test_every_device_present_and_running_still_reads_one_hundred(self):
        rows = [av_row(i + 1) for i in range(10)]
        out = run(report(rows, self.fleet(10)))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesNotInReport"] == 0

    def test_no_device_in_the_report_but_a_device_list_is_not_a_hundred(self):
        # A row for a device that is not in the list does not rescue the missing ones.
        out = run(report([av_row(99)], self.fleet(4)))
        assert value(out) == 20

    def test_phones_and_tablets_without_a_row_are_left_out(self):
        devices = [device(1), device(2, node_class="APPLE_IOS"), device(3, node_class="ANDROID"), device(4)]
        out = run(report([av_row(1)], devices))
        assert value(out) == 50
        scope = out["transformedResponse"]
        assert scope["devicesNotInReport"] == 1
        assert scope["devicesNotInReportLeftOut"] == 2

    def test_devices_unseen_for_fifteen_days_without_a_row_are_left_out(self):
        devices = [device(1), device(2, seen=NOW - 40 * 86400), device(3)]
        out = run(report([av_row(1)], devices))
        assert value(out) == 50
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_last_contact_far_in_the_future_is_not_a_contact(self):
        devices = [device(1), device(2, seen=NOW + 400 * 86400)]
        out = run(report([av_row(1)], devices))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_missing_device_with_no_last_contact_counts_against(self):
        devices = [device(1), {"id": 2, "nodeClass": "WINDOWS_WORKSTATION"}]
        out = run(report([av_row(1)], devices))
        assert value(out) == 50

    def test_a_device_listed_twice_counts_once(self):
        devices = [device(1), device(2), device(2)]
        out = run(report([av_row(1)], devices))
        assert value(out) == 50

    def test_a_device_whose_rows_were_left_out_is_not_also_counted_as_missing(self):
        old = NOW - 40 * 86400
        devices = [device(1), device(2)]
        out = run(report([av_row(1), av_row(2, seen=old)], devices))
        assert value(out) == 100
        scope = out["transformedResponse"]
        assert scope["devicesLeftOutStale"] == 1
        assert scope["devicesNotInReport"] == 0


    def test_the_missing_count_is_in_the_reason(self):
        out = run(report([av_row(1)], self.fleet(4)))
        text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
        assert "3" in text and "no antivirus-status row" in text


class TestUnreadableDeviceListIsNotEvaluated:
    """The device list is the roster the percentage is measured against. Without a readable one a device the
    report does not mention cannot be counted, so the report-only percentage could pass a fleet it never saw.
    The answer is None (not evaluated), never a value."""

    ROWS = [av_row(1), av_row(2)]

    @pytest.mark.parametrize("devices", [
        None,
        "not a list",
        42,
        True,
        {},
        {"error": "Forbidden"},
        {"errors": ["Forbidden"]},
        {"status": 403},
        {"statusCode": 500, "message": "boom"},
        {"data": "nope"},
        {"results": None},
        {"data": fleet_of(3), "error": "Forbidden"},
    ])
    def test_an_absent_or_unreadable_device_list_is_not_evaluated(self, devices):
        body = report(self.ROWS, devices)
        if devices is None:
            assert "devices" not in body
        out = run(body)
        assert value(out) is None
        assert not_evaluated(out)

    def test_the_reason_names_the_device_list(self):
        out = run(report(self.ROWS, None))
        errors = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
        assert "device list" in errors

    def test_a_bare_list_of_rows_has_no_device_list_and_is_not_evaluated(self):
        out = run(self.ROWS)
        assert value(out) is None
        assert not_evaluated(out)

    def test_a_well_formed_empty_list_with_report_rows_is_a_real_value(self):
        out = run(report(self.ROWS, []))
        assert value(out) == 100
        assert out["transformedResponse"]["devicesNotInReport"] == 0
        assert out["transformedResponse"]["deviceListRead"] is True

    def test_a_well_formed_empty_list_inside_a_data_wrapper_is_a_real_value(self):
        out = run(report(self.ROWS, {"data": []}))
        assert value(out) == 100

    @pytest.mark.parametrize("rows", [[], None])
    def test_a_well_formed_empty_list_without_report_rows_is_not_evaluated(self, rows):
        body = {"devices": []} if rows is None else {"results": rows, "devices": []}
        out = run(body)
        assert value(out) is None
        assert not_evaluated(out)

    def test_a_readable_list_beside_rows_is_measured(self):
        out = run(report(self.ROWS, fleet_of(4)))
        assert value(out) == 50
        assert not not_evaluated(out)


class TestStringEncodedReply:
    """The engine can hand the reply over as a JSON string or bytes. An error reply must be read as an error either way,
    and a clean one measured, exactly as the other NinjaOne antivirus-status checks do."""

    def encoded(self, **extra):
        body = report([av_row(1), av_row(2)])
        body.update(extra)
        return json.dumps(body)

    @pytest.mark.parametrize("extra", [{"error": "Forbidden"}, {"errors": ["Forbidden"]}, {"status": 403}, {"statusCode": 500}])
    def test_a_string_encoded_error_reply_is_flagged_as_an_error(self, extra):
        out = run(self.encoded(**extra))
        assert value(out) is None
        assert not_evaluated(out)
        assert "instead of a measurement" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])

    def test_a_bytes_encoded_error_reply_is_flagged_as_an_error(self):
        out = run(self.encoded(error="Forbidden").encode("utf-8"))
        assert value(out) is None
        assert "instead of a measurement" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])

    def test_a_string_encoded_clean_reply_is_measured(self):
        out = run(self.encoded())
        assert value(out) == 100
        assert not not_evaluated(out)

    def test_a_bytes_encoded_clean_reply_is_measured(self):
        assert value(run(self.encoded().encode("utf-8"))) == 100

    @pytest.mark.parametrize("body", ["not json", "", b"\xff\xfe", "[1, 2"])
    def test_an_unparseable_reply_is_not_evaluated(self, body):
        out = run(body)
        assert value(out) is None
        assert not_evaluated(out)
