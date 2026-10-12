"""NinjaOne isEPPConfigured counts endpoint protection only from a real antivirus or EPP product state per device.

A policy id says which NinjaOne policy a device uses, not that a protection product is installed or
running. So the device list alone (policyId set, policyId empty because the policy is inherited from the
role, or anything else) never reads positive and never reads as a fail: with no product data the check is
not evaluated (None). With the antivirus-status report the value is the whole-number percentage of judged
devices that have a product reporting ON. Synthetic data only."""
import importlib.util
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


def report(rows, devices=None):
    body = {"results": rows}
    if devices is not None:
        body["devices"] = devices
    return body


def value(out):
    return out["transformedResponse"]["isEPPConfigured"]


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

    def test_without_a_device_list_the_report_alone_is_judged(self):
        out = run(report([av_row(1), av_row(2)]))
        assert value(out) == 100
        assert out["transformedResponse"]["deviceListRead"] is False

    def test_an_unreadable_device_list_is_treated_as_not_read(self):
        out = run({"results": [av_row(1), av_row(2)], "devices": "not a list"})
        assert value(out) == 100
        assert out["transformedResponse"]["deviceListRead"] is False

    def test_the_missing_count_is_in_the_reason(self):
        out = run(report([av_row(1)], self.fleet(4)))
        text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
        assert "3" in text and "no antivirus-status row" in text
