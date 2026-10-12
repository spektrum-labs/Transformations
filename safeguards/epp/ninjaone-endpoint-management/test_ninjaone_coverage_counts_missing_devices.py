"""NinjaOne coverage percentage and unprotected count: a device the report does not mention is not shown protected.

requiredCoveragePercentage and endpointOperationalStatusUnprotectedCount read the antivirus-status report, which has
one row per product per device. A device that has no row at all (an agent that never reported, a device the report
left out) cannot be shown protected, so it must count against the percentage and in the unprotected count, never be
silently dropped. The device list (workflow key "devices") rides beside the report and is the roster to measure against.
Phones and tablets, and devices not seen within 15 days, are still left out, as in every other endpoint rule.
Synthetic data only."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()
DAY = 86400.0

COVERAGE = "requiredCoveragePercentage"
UNPROTECTED = "endpointOperationalStatusUnprotectedCount"
BOTH = [COVERAGE, UNPROTECTED]
THREE = ["isEPPConfigured", COVERAGE, UNPROTECTED]


def run(name, body):
    spec = importlib.util.spec_from_file_location("nj_missing_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def value(name, out):
    return out["transformedResponse"][name]


def not_evaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


def device(did, node_class="WINDOWS_WORKSTATION", seen=None):
    return {"id": did, "organizationId": 10, "nodeClass": node_class, "policyId": None,
            "rolePolicyId": 101, "lastContact": NOW if seen is None else seen}


def av_row(did, product="Defender", state="ON", seen=None):
    return {"deviceId": did, "productName": product, "productState": state, "definitionStatus": "Up-to-Date",
            "timestamp": NOW if seen is None else seen}


def report(rows, devices=None):
    body = {"results": rows}
    if devices is not None:
        body["devices"] = devices
    return body


def fleet(n):
    return [device(i + 1) for i in range(n)]


def expected(name, protected, missing_or_off):
    """The check's value when `protected` devices are covered and `missing_or_off` are not."""
    if name != UNPROTECTED:
        total = protected + missing_or_off
        return (protected * 100) // total
    return missing_or_off


@pytest.mark.parametrize("name", BOTH)
class TestDevicesMissingFromTheReportCountAgainst:
    def test_two_running_of_ten_devices(self, name):
        out = run(name, report([av_row(1), av_row(2)], fleet(10)))
        assert value(name, out) == expected(name, 2, 8)
        assert out["transformedResponse"]["devicesNotInReport"] == 8
        assert out["transformedResponse"]["deviceListRead"] is True
        assert not not_evaluated(out)

    def test_every_device_present_and_running_is_unchanged(self, name):
        rows = [av_row(i + 1) for i in range(10)]
        out = run(name, report(rows, fleet(10)))
        assert value(name, out) == expected(name, 10, 0)
        assert out["transformedResponse"]["devicesNotInReport"] == 0

    def test_a_row_for_a_device_not_in_the_list_does_not_rescue_the_missing_ones(self, name):
        out = run(name, report([av_row(99)], fleet(4)))
        assert value(name, out) == expected(name, 1, 4)

    def test_a_device_with_a_row_that_is_off_counts_once_not_twice(self, name):
        # Device 2 is in the report with the product OFF. It is not also "missing".
        out = run(name, report([av_row(1), av_row(2, state="OFF")], fleet(3)))
        assert value(name, out) == expected(name, 1, 2)
        assert out["transformedResponse"]["devicesNotInReport"] == 1

    def test_phones_and_tablets_without_a_row_are_left_out(self, name):
        devices = [device(1), device(2, node_class="APPLE_IOS"), device(3, node_class="ANDROID"), device(4)]
        out = run(name, report([av_row(1)], devices))
        assert value(name, out) == expected(name, 1, 1)
        scope = out["transformedResponse"]
        assert scope["devicesNotInReport"] == 1
        assert scope["devicesNotInReportLeftOut"] == 2

    def test_devices_unseen_for_fifteen_days_without_a_row_are_left_out(self, name):
        devices = [device(1), device(2, seen=NOW - 40 * DAY), device(3)]
        out = run(name, report([av_row(1)], devices))
        assert value(name, out) == expected(name, 1, 1)
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_last_contact_far_in_the_future_is_not_a_contact(self, name):
        devices = [device(1), device(2, seen=NOW + 400 * DAY)]
        out = run(name, report([av_row(1)], devices))
        assert value(name, out) == expected(name, 1, 0)
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_missing_device_with_no_last_contact_counts_against(self, name):
        devices = [device(1), {"id": 2, "nodeClass": "WINDOWS_WORKSTATION"}]
        out = run(name, report([av_row(1)], devices))
        assert value(name, out) == expected(name, 1, 1)

    def test_a_device_listed_twice_counts_once(self, name):
        devices = [device(1), device(2), device(2)]
        out = run(name, report([av_row(1)], devices))
        assert value(name, out) == expected(name, 1, 1)

    def test_a_device_whose_rows_were_left_out_is_not_also_counted_as_missing(self, name):
        devices = [device(1), device(2)]
        out = run(name, report([av_row(1), av_row(2, seen=NOW - 40 * DAY)], devices))
        assert value(name, out) == expected(name, 1, 0)
        scope = out["transformedResponse"]
        assert scope["devicesLeftOutStale"] == 1
        assert scope["devicesNotInReport"] == 0

    def test_a_device_whose_only_row_has_no_product_name_is_not_also_counted_as_missing(self, name):
        # The row is unreadable and left out of the judging; the device is still in the report.
        rows = [av_row(1), {"deviceId": 2, "productName": None, "productState": None, "timestamp": NOW}]
        out = run(name, report(rows, fleet(2)))
        assert value(name, out) == expected(name, 1, 0)
        assert out["transformedResponse"]["devicesNotInReport"] == 0

    def test_a_well_formed_empty_device_list_with_report_rows_is_a_real_value(self, name):
        for empty in ([], {"data": []}, {"results": []}):
            out = run(name, report([av_row(1), av_row(2)], empty))
            assert value(name, out) == expected(name, 2, 0)
            assert out["transformedResponse"]["deviceListRead"] is True

    def test_the_device_list_may_ride_in_a_data_wrapper(self, name):
        body = {"results": [av_row(1)], "devices": {"data": fleet(3)}}
        out = run(name, body)
        assert value(name, out) == expected(name, 1, 2)

    def test_the_missing_count_is_in_the_reason(self, name):
        out = run(name, report([av_row(1)], fleet(4)))
        text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
        assert "3" in text and "no antivirus-status row" in text

    def test_missing_devices_are_never_a_pass_reason(self, name):
        out = run(name, report([av_row(1), av_row(2)], fleet(3)))
        assert out["additionalInfo"]["evaluation"]["passReasons"] == []
        assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("name", BOTH)
class TestNothingToJudgeStaysNotEvaluated:
    def test_a_device_list_with_no_report_rows_is_not_evaluated(self, name):
        out = run(name, {"results": [], "devices": fleet(5)})
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_device_list_alone_is_not_evaluated(self, name):
        out = run(name, {"devices": fleet(5)})
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_an_error_reply_with_a_device_list_is_not_evaluated(self, name):
        out = run(name, {"results": [av_row(1)], "devices": fleet(5), "error": "Forbidden"})
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_fully_stale_report_with_a_device_list_is_not_evaluated(self, name):
        old = NOW - 40 * DAY
        out = run(name, report([av_row(1, seen=old), av_row(2, seen=old)], fleet(5)))
        assert value(name, out) is None
        assert not_evaluated(out)


def test_the_unprotected_count_adds_missing_devices_to_the_ones_that_report_off():
    out = run(UNPROTECTED, report([av_row(1), av_row(2, state="OFF"), av_row(3, product="NONE", state=None)], fleet(6)))
    # Device 1 protected; device 2 OFF and device 3 NONE are unprotected in the report; devices 4-6 are missing.
    assert value(UNPROTECTED, out) == 5
    assert out["transformedResponse"]["devicesNotInReport"] == 3


def test_the_coverage_percentage_floors_with_missing_devices_in_the_denominator():
    out = run(COVERAGE, report([av_row(1), av_row(2), av_row(3)], fleet(7)))
    assert value(COVERAGE, out) == 42  # 3 of 7 = 42.8, floored, never rounded up


@pytest.mark.parametrize("name", BOTH)
class TestUnreadableDeviceListIsNotEvaluated:
    """The device list is the roster the result is measured against. Without a readable one a device the report does
    not mention cannot be counted, so a result from the report alone could pass a fleet it never saw: None, never a value."""

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
        {"statusCode": "500"},
        {"status_code": " 401 "},
        {"data": "nope"},
        {"results": None},
        {"data": [device(1), device(2)], "error": "Forbidden"},
    ])
    def test_an_absent_or_unreadable_device_list_is_not_evaluated(self, name, devices):
        body = report(self.ROWS, devices)
        if devices is None:
            assert "devices" not in body
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_the_reason_names_the_device_list(self, name):
        out = run(name, report(self.ROWS, None))
        assert "device list" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])

    def test_a_bare_list_of_rows_has_no_device_list_and_is_not_evaluated(self, name):
        out = run(name, self.ROWS)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_well_formed_empty_list_without_report_rows_is_not_evaluated(self, name):
        for body in ({"devices": []}, {"results": [], "devices": []}):
            out = run(name, body)
            assert value(name, out) is None
            assert not_evaluated(out)


@pytest.mark.parametrize("name", THREE)
class TestMissingDevicesUseTheSameWindowAsTheReportRows:
    """A device with a report row is judged against 15 days before the newest row (not before now). A device with no
    row is judged against the same cutoff, so the two kinds of device are held to one window. Without this a device last
    seen 15.5 days ago was kept when it had a row and silently dropped when it had none."""

    def test_a_device_just_outside_fifteen_days_of_now_but_inside_the_report_window_counts(self, name):
        rows = [av_row(1, seen=NOW - 1 * DAY)]
        devices = [device(1, seen=NOW - 1 * DAY), device(2, seen=NOW - 15.5 * DAY)]
        out = run(name, report(rows, devices))
        assert value(name, out) == expected(name, 1, 1)
        assert out["transformedResponse"]["devicesNotInReport"] == 1
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 0

    def test_a_device_older_than_the_report_window_is_left_out(self, name):
        rows = [av_row(1, seen=NOW - 1 * DAY)]
        devices = [device(1, seen=NOW - 1 * DAY), device(2, seen=NOW - 17 * DAY)]
        out = run(name, report(rows, devices))
        assert value(name, out) == expected(name, 1, 0)
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_when_the_newest_row_is_older_the_window_moves_with_it(self, name):
        # Newest row is 10 days old, so the window starts 25 days back; a device last seen 24 days ago is inside it.
        rows = [av_row(1, seen=NOW - 10 * DAY)]
        devices = [device(1, seen=NOW - 10 * DAY), device(2, seen=NOW - 24 * DAY), device(3, seen=NOW - 26 * DAY)]
        out = run(name, report(rows, devices))
        assert out["transformedResponse"]["devicesNotInReport"] == 1
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_far_future_row_does_not_move_the_window(self, name):
        rows = [av_row(1, seen=NOW + 400 * DAY), av_row(2, seen=NOW - 1 * DAY)]
        devices = [device(1), device(2), device(3, seen=NOW - 15.5 * DAY), device(4, seen=NOW - 20 * DAY)]
        out = run(name, report(rows, devices))
        assert out["transformedResponse"]["devicesNotInReport"] == 1
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1

    def test_a_device_in_the_future_is_still_left_out(self, name):
        rows = [av_row(1)]
        devices = [device(1), device(2, seen=NOW + 400 * DAY)]
        out = run(name, report(rows, devices))
        assert out["transformedResponse"]["devicesNotInReportLeftOut"] == 1
