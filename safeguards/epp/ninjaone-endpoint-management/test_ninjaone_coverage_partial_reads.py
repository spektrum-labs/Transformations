"""NinjaOne coverage percentage, configured percentage and unprotected count: a read that is only part of the fleet is not a total.

requiredCoveragePercentage, isEPPConfigured and endpointOperationalStatusUnprotectedCount measure the antivirus-status
report against the device list that rides beside it (workflow key "devices"). When either one is only a page of the fleet,
the devices on the pages nobody read are not "missing": they are unseen. A percentage or a count taken from part of the
fleet is not a total, so all three checks read Not evaluated (value None, dataCollection.status "error", a non-empty errors
list).

Row shape: the report carries one row per product per device (a device with two products has two rows, and a device with
none has one row named NONE), and nothing says the rows of one device sit together. A device seen with no running product
on one page can therefore have its running product on a page nobody read, so a seen unprotected device is not proven
unprotected on a partial read. There is no floor to report: the unprotected count reads None and unprotectedCountAtLeast
is None too. A percentage has no floor either, so it reads None.

Shapes: the report's own cursor object is {"name", "offset", "count", "expires"}; its count is the number of rows the
query holds. A report whose cursor.count is above the rows received is partial. A device-list wrapper is partial when it
carries a next-page marker or a cursor.count above its list. The live joined body has "cursor": [] and a plain list of
devices, and that stays a complete read. Synthetic data only."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()

COVERAGE = "requiredCoveragePercentage"
CONFIGURED = "isEPPConfigured"
UNPROTECTED = "endpointOperationalStatusUnprotectedCount"
BOTH = [COVERAGE, CONFIGURED, UNPROTECTED]


def run(name, body):
    spec = importlib.util.spec_from_file_location("nj_partial_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def value(name, out):
    return out["transformedResponse"][name]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def not_evaluated(out):
    return collection(out)["status"] == "error" and len(collection(out)["errors"]) > 0


def device(did, node_class="WINDOWS_WORKSTATION"):
    return {"id": did, "organizationId": 10, "nodeClass": node_class, "policyId": None,
            "rolePolicyId": 101, "lastContact": NOW}


def av_row(did, state="ON"):
    return {"deviceId": did, "productName": "Defender", "productState": state,
            "definitionStatus": "Up-to-Date", "timestamp": NOW}


def fleet(n):
    return [device(i + 1) for i in range(n)]


def cursor(count):
    return {"name": "c1", "offset": 0, "count": count, "expires": 0}


def expected(name, protected, missing_or_off):
    if name != UNPROTECTED:
        return (protected * 100) // (protected + missing_or_off)
    return missing_or_off


@pytest.mark.parametrize("name", BOTH)
class TestAReportWithMoreRowsThanItHoldsIsPartial:
    def test_a_cursor_count_above_the_rows_received_is_not_evaluated(self, name):
        rows = [av_row(i + 1) for i in range(10)]
        body = {"results": rows, "devices": fleet(10), "cursor": cursor(40)}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_the_unread_rows_are_not_counted_as_devices_missing_from_the_report(self, name):
        # Two rows came back of a report that holds 500. The other eight listed devices may be on the unread rows.
        body = {"results": [av_row(1), av_row(2)], "devices": fleet(10), "cursor": cursor(500)}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_cursor_count_sent_as_text_is_read_as_the_number(self, name):
        body = {"results": [av_row(1), av_row(2)], "devices": fleet(2), "cursor": cursor("40")}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_cursor_count_equal_to_the_rows_received_is_a_complete_read(self, name):
        rows = [av_row(1), av_row(2)]
        out = run(name, {"results": rows, "devices": fleet(4), "cursor": cursor(2)})
        assert value(name, out) == expected(name, 2, 2)
        assert not not_evaluated(out)

    def test_the_live_empty_cursor_list_is_a_complete_read(self, name):
        rows = [av_row(1), av_row(2)]
        out = run(name, {"results": rows, "devices": fleet(4), "cursor": []})
        assert value(name, out) == expected(name, 2, 2)
        assert not not_evaluated(out)

    @pytest.mark.parametrize("cur", [{"name": "c1"}, {"name": "c1", "offset": 0, "count": None, "expires": 0},
                                     {"name": "c1", "count": "n/a"}])
    def test_a_cursor_that_names_itself_and_gives_no_count_is_partial(self, name, cur):
        body = {"results": [av_row(1), av_row(2)], "devices": fleet(2), "cursor": cur}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    @pytest.mark.parametrize("offset", [50, "50", 1])
    def test_a_cursor_offset_above_zero_means_the_body_starts_after_the_first_row_and_is_partial(self, name, offset):
        cur = {"name": "c1", "offset": offset, "count": 2, "expires": 0}
        out = run(name, {"results": [av_row(1), av_row(2)], "devices": fleet(2), "cursor": cur})
        assert value(name, out) is None
        assert not_evaluated(out)

    @pytest.mark.parametrize("offset", [0, "0", None, "", "n/a"])
    def test_a_cursor_offset_of_zero_or_unreadable_is_not_a_partial_signal_on_its_own(self, name, offset):
        cur = {"name": "c1", "offset": offset, "count": 2, "expires": 0}
        out = run(name, {"results": [av_row(1), av_row(2)], "devices": fleet(4), "cursor": cur})
        assert value(name, out) == expected(name, 2, 2)
        assert not not_evaluated(out)

    def test_a_cursor_with_no_name_and_no_count_is_a_complete_read(self, name):
        rows = [av_row(1), av_row(2)]
        out = run(name, {"results": rows, "devices": fleet(4), "cursor": {"name": None, "offset": 0, "expires": 0}})
        assert value(name, out) == expected(name, 2, 2)
        assert not not_evaluated(out)

    def test_a_next_page_marker_on_the_report_is_partial(self, name):
        body = {"results": [av_row(1), av_row(2)], "devices": fleet(2), "next": "page-2"}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_a_truncation_flag_on_the_report_is_partial(self, name):
        body = {"results": [av_row(1), av_row(2)], "devices": fleet(2), "truncated": True}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)


@pytest.mark.parametrize("name", BOTH)
class TestADeviceListWithMoreDevicesThanItHoldsIsPartial:
    def rows(self):
        return [av_row(i + 1) for i in range(4)]

    @pytest.mark.parametrize("marker", [
        {"next": "abc"},
        {"nextPage": 2},
        {"nextToken": "t2"},
        {"cursor": "after-4"},
        {"cursor": cursor(25)},
        {"hasMore": True},
        {"has_more": "true"},
        {"truncated": True},
    ])
    def test_a_device_wrapper_with_a_next_page_or_cursor_marker_is_not_evaluated(self, name, marker):
        wrapper = dict({"data": fleet(4)}, **marker)
        out = run(name, {"results": self.rows(), "devices": wrapper})
        assert value(name, out) is None
        assert not_evaluated(out)

    @pytest.mark.parametrize("marker", [
        {"next": None},
        {"next": ""},
        {"next": "null"},
        {"nextToken": "None"},
        {"cursor": []},
        {"cursor": cursor(4)},
        {"hasMore": False},
        {"truncated": "false"},
    ])
    def test_a_device_wrapper_with_no_marker_set_is_a_complete_read(self, name, marker):
        wrapper = dict({"data": fleet(4)}, **marker)
        out = run(name, {"results": self.rows(), "devices": wrapper})
        assert value(name, out) == expected(name, 4, 0)
        assert not not_evaluated(out)

    def test_a_plain_device_list_is_unchanged(self, name):
        out = run(name, {"results": self.rows(), "devices": fleet(6)})
        assert value(name, out) == expected(name, 4, 2)
        assert not not_evaluated(out)

    def test_a_results_wrapper_is_read_the_same_way(self, name):
        out = run(name, {"results": self.rows(), "devices": {"results": fleet(4), "next": "p2"}})
        assert value(name, out) is None
        assert not_evaluated(out)


class TestAPartialCountIsNeitherATotalNorAFloor:
    """A seen unprotected device is not proven unprotected on a partial read: the report holds one row per product per
    device and is not guaranteed to keep a device's rows together, so the running product can be on an unread page. There
    is no floor to report, and a floor could grade a pass against any threshold above zero anyway (3 seen, a limit of 5, a
    real count of 10). The count is None and so is unprotectedCountAtLeast."""
    name = UNPROTECTED

    def check(self, out):
        assert value(self.name, out) is None
        assert out["transformedResponse"]["unprotectedCountAtLeast"] is None
        assert out["transformedResponse"]["totalDevices"] is None
        assert out["transformedResponse"]["partialRead"] is True
        assert not_evaluated(out)

    def test_a_partial_report_with_seen_off_devices_has_no_floor(self):
        rows = [av_row(1), av_row(2, state="OFF"), av_row(3, state="OFF")]
        self.check(run(self.name, {"results": rows, "devices": fleet(10), "cursor": cursor(100)}))

    def test_a_partial_device_list_with_a_seen_off_device_has_no_floor(self):
        rows = [av_row(1), av_row(2, state="OFF")]
        self.check(run(self.name, {"results": rows, "devices": {"data": fleet(10), "next": "p2"}}))

    def test_a_device_seen_with_no_product_may_have_one_on_the_unread_page(self):
        # Device 1 shows an OFF product and a NONE row here; its running product can sit on the page nobody read.
        rows = [av_row(1, state="OFF"), {"deviceId": 2, "productName": "NONE", "timestamp": NOW}]
        self.check(run(self.name, {"results": rows, "devices": fleet(10), "cursor": cursor(900)}))

    def test_devices_missing_from_a_partial_read_are_not_counted(self):
        rows = [av_row(1, state="OFF")]
        self.check(run(self.name, {"results": rows, "devices": fleet(50), "cursor": cursor(900)}))

    def test_a_partial_read_with_every_seen_device_running_has_no_floor_either(self):
        rows = [av_row(1), av_row(2)]
        self.check(run(self.name, {"results": rows, "devices": fleet(2), "cursor": cursor(900)}))

    def test_the_reason_says_the_figure_is_not_a_total(self):
        rows = [av_row(1, state="OFF")]
        out = run(self.name, {"results": rows, "devices": fleet(3), "cursor": cursor(900)})
        assert "only part of the fleet" in " ".join(collection(out)["errors"])


@pytest.mark.parametrize("name", [COVERAGE, CONFIGURED])
class TestAPercentageFromPartOfTheFleetIsNotAFigure:
    def test_a_partial_read_with_a_seen_off_device_still_reads_none(self, name):
        rows = [av_row(1), av_row(2, state="OFF")]
        out = run(name, {"results": rows, "devices": fleet(10), "cursor": cursor(100)})
        assert value(name, out) is None
        assert out["transformedResponse"]["totalDevices"] is None
        assert out["transformedResponse"]["partialRead"] is True
        assert not_evaluated(out)

    def test_a_partial_read_never_reports_a_percentage_or_a_device_total_whatever_the_seen_rows_show(self, name):
        for rows in ([av_row(1)], [av_row(1, state="OFF")], [av_row(1), av_row(2, state="OFF")]):
            out = run(name, {"results": rows, "devices": fleet(3), "cursor": cursor(300)})
            assert value(name, out) is None
            assert out["transformedResponse"]["totalDevices"] is None
            assert not_evaluated(out)
