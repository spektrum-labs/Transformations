"""PortSwigger Burp Suite DAST checks.

Bodies follow the Burp Suite DAST GraphQL schema (portswigger.net/burp/extensibility/dast/graphql-api, read
2026-11-13) for the exact queries the Integration-Service definition sends: schedule_items for
isDASTScanScheduled, scans(scan_status: [succeeded], sort_column: end) for isDASTScanCurrent and the two issue
counts, scans(sort_column: start) for failedDASTScanTargetsCount. Every id, name and URL is synthetic."""
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
NOW = datetime.now(timezone.utc)

FILES = {
    "isDASTScanScheduled": "isdastscanscheduled",
    "isDASTScanCurrent": "isdastscancurrent",
    "dastHighSeverityIssuesCount": "dasthighseverityissuescount",
    "dastMediumSeverityIssuesCount": "dastmediumseverityissuescount",
    "failedDASTScanTargetsCount": "faileddastscantargetscount",
}
FIELD = {"isDASTScanScheduled": "schedule_items"}


def load_plain(key):
    name = FILES[key]
    spec = importlib.util.spec_from_file_location("burpdast_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed(key):
    """The same file through the Token-Service RestrictedPython namespace (tools/restricted_sandbox.py)."""
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(os.path.join(HERE, FILES[key] + ".py")) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def run(key, payload, loader=load_plain):
    return loader(key)(payload)


def value(key, payload, loader=load_plain):
    return run(key, payload, loader)["transformedResponse"][key]


def collection(out):
    return out["additionalInfo"]["dataCollection"]["status"]


def ts(days_ago=0, hours=0):
    return (NOW - timedelta(days=days_ago, hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.") + "123Z"


def graphql(field, items):
    return {"data": {field: items}}


def site(sid, name):
    return {"id": sid, "name": name}


def schedule_item(iid, rrule, next_days=7, sites=None, folders=None):
    return {"id": iid, "scheduled_run_time": None if next_days is None else ts(-next_days),
            "has_run_more_than_once": True,
            "schedule": {"initial_run_time": ts(200), "rrule": rrule},
            "sites": [site("101", "storefront.example.test")] if sites is None else sites,
            "folders": [] if folders is None else folders,
            "scan_configurations": [{"id": "cfg-1", "name": "Crawl and Audit - Balanced"}]}


def band(total, certain=0):
    return {"total": total, "certain": certain, "firm": total - certain, "tentative": 0}


def completed(sid, target, days, high=0, medium=0, status="succeeded"):
    return {"id": sid, "status": status, "start_time": ts(days, 2), "end_time": ts(days),
            "duration_in_seconds": 7200, "scan_target": {"id": target, "name": "app-" + target + ".example.test",
                                                          "type": "site"},
            "schedule_item": {"id": "si-1"},
            "issue_counts": {"total": high + medium + 3, "high": band(high, certain=high), "medium": band(medium),
                             "low": band(2), "info": {"total": 1}},
            "scan_delta": {"new_issue_count": 0, "regressed_issue_count": 0, "repeated_issue_count": high + medium,
                           "resolved_issue_count": 0}}


def recent(sid, target, days, status, message=None):
    finished = status in ("succeeded", "failed", "cancelled")
    return {"id": sid, "status": status, "start_time": ts(days, 3), "end_time": ts(days) if finished else None,
            "scan_target": {"id": target, "name": "app-" + target + ".example.test", "type": "site"},
            "schedule_item": {"id": "si-1"},
            "scan_failure_code": 12 if status == "failed" else None,
            "scan_failure_message": message if status == "failed" else None}


def field_of(key):
    return FIELD.get(key, "scans")


# ---------------------------------------------------------------------------------------------- every check


@pytest.mark.parametrize("key", sorted(FILES))
@pytest.mark.parametrize("body", [
    {},
    None,
    "",
    "not json",
    {"data": None, "errors": [{"message": "Unauthorized", "extensions": {"code": 3}}]},
    {"error": True, "statusCode": 401, "message": "Unauthorized"},
    {"statusCode": 503, "message": "Service Unavailable"},
    {"message": "Internal server error"},
], ids=["empty-object", "none", "empty-string", "not-json", "graphql-errors-only", "is-error", "http-503",
        "message-only"])
def test_a_body_that_proves_nothing_is_not_evaluated(key, body):
    out = run(key, body)
    assert out["transformedResponse"][key] is None
    assert collection(out) == "error"


@pytest.mark.parametrize("key", sorted(FILES))
def test_a_null_root_field_is_not_evaluated(key):
    out = run(key, graphql(field_of(key), None))
    assert out["transformedResponse"][key] is None
    assert collection(out) == "error"


@pytest.mark.parametrize("key", sorted(FILES))
def test_graphql_errors_beside_partial_data_are_not_evaluated(key):
    body = graphql(field_of(key), [])
    body["errors"] = [{"message": "Access denied to some sites"}]
    assert value(key, body) is None


@pytest.mark.parametrize("key", sorted(FILES))
def test_an_entry_that_is_not_an_object_is_not_evaluated(key):
    assert value(key, graphql(field_of(key), ["oops"])) is None


PASSING = {
    "isDASTScanScheduled": graphql("schedule_items", [schedule_item("si-1", "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO")]),
    "isDASTScanCurrent": graphql("scans", [completed("s1", "101", 3)]),
    "dastHighSeverityIssuesCount": graphql("scans", [completed("s1", "101", 3)]),
    "dastMediumSeverityIssuesCount": graphql("scans", [completed("s1", "101", 3)]),
    "failedDASTScanTargetsCount": graphql("scans", [recent("s1", "101", 3, "succeeded")]),
}
FAILING = {
    "isDASTScanScheduled": graphql("schedule_items", [schedule_item("si-1", "")]),
    "isDASTScanCurrent": graphql("scans", [completed("s1", "101", 60)]),
    "dastHighSeverityIssuesCount": graphql("scans", [completed("s1", "101", 3, high=2)]),
    "dastMediumSeverityIssuesCount": graphql("scans", [completed("s1", "101", 3, medium=4)]),
    "failedDASTScanTargetsCount": graphql("scans", [recent("s1", "101", 3, "failed", "Unable to reach the site")]),
}
PASS_VALUE = {"isDASTScanScheduled": True, "isDASTScanCurrent": True, "dastHighSeverityIssuesCount": 0,
              "dastMediumSeverityIssuesCount": 0, "failedDASTScanTargetsCount": 0}
FAIL_VALUE = {"isDASTScanScheduled": False, "isDASTScanCurrent": False, "dastHighSeverityIssuesCount": 2,
              "dastMediumSeverityIssuesCount": 4, "failedDASTScanTargetsCount": 1}


def shapes(body):
    """The ways the same GraphQL answer reaches a transform: as Burp sends it, drilled by Token-Service's legacy
    envelope walk (which strips "data"), under the Integration-Service envelope, as a JSON string, as bytes."""
    inner = body["data"]
    return [body, inner, {"response": {"result": {"apiResponse": body}}}, {"apiResponse": inner},
            json.dumps(body), json.dumps(body).encode("utf-8")]


@pytest.mark.parametrize("key", sorted(FILES))
def test_pass_and_fail_read_the_same_in_every_envelope(key):
    for shape in shapes(PASSING[key]):
        assert value(key, shape) == PASS_VALUE[key]
    for shape in shapes(FAILING[key]):
        assert value(key, shape) == FAIL_VALUE[key]


@pytest.mark.parametrize("key", sorted(FILES))
def test_the_production_sandbox_gives_the_same_answers(key):
    for body, expected in ((PASSING[key], PASS_VALUE[key]), (FAILING[key], FAIL_VALUE[key]), ({}, None)):
        out = run(key, body, loader=load_sandboxed)
        assert out["transformedResponse"][key] == expected
        assert collection(out) == ("error" if expected is None else "success")


@pytest.mark.parametrize("key", sorted(FILES))
def test_metadata_names_the_vendor_and_category(key):
    meta = run(key, PASSING[key])["additionalInfo"]["metadata"]
    assert meta["vendor"] == "PortSwigger Burp Suite DAST"
    assert meta["category"] == "Application Security"
    assert meta["transformationId"] == FILES[key]


# ---------------------------------------------------------------------------------------------- isDASTScanScheduled

SCHEDULED = "isDASTScanScheduled"


def test_a_weekly_schedule_on_a_site_passes_and_names_it():
    out = run(SCHEDULED, PASSING[SCHEDULED])
    assert out["transformedResponse"]["scanFrequencies"] == ["WEEKLY"]
    assert "storefront.example.test" in out["additionalInfo"]["evaluation"]["passReasons"][0]


def test_a_schedule_on_a_folder_counts():
    item = schedule_item("si-1", "FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=19", sites=[],
                         folders=[{"id": "f-1", "name": "Customer portals"}])
    assert value(SCHEDULED, graphql("schedule_items", [item])) is True


@pytest.mark.parametrize("item", [
    schedule_item("si-1", ""),
    schedule_item("si-1", None),
    schedule_item("si-1", "FREQ=DAILY;COUNT=10;INTERVAL=1", next_days=None),
    schedule_item("si-1", "FREQ=WEEKLY;INTERVAL=1", sites=[], folders=[]),
], ids=["one-off-empty-rrule", "one-off-null-rrule", "recurrence-ended", "covers-nothing"])
def test_no_recurring_schedule_with_a_next_run_on_a_target_fails(item):
    out = run(SCHEDULED, graphql("schedule_items", [item]))
    assert out["transformedResponse"][SCHEDULED] is False
    assert out["additionalInfo"]["evaluation"]["failReasons"]


def test_no_schedules_at_all_fails():
    assert value(SCHEDULED, graphql("schedule_items", [])) is False


@pytest.mark.parametrize("item", [
    {"id": "si-1", "scheduled_run_time": ts(-1), "sites": [], "folders": []},
    schedule_item("si-1", "INTERVAL=1;BYDAY=MO"),
    schedule_item("si-1", 7),
    dict(schedule_item("si-1", "FREQ=WEEKLY"), scheduled_run_time="next tuesday"),
    dict(schedule_item("si-1", "FREQ=WEEKLY"), sites=None),
], ids=["no-schedule", "rrule-without-freq", "rrule-not-text", "unreadable-next-run", "null-sites"])
def test_an_unreadable_schedule_item_is_not_evaluated_unless_another_recurs(item):
    assert value(SCHEDULED, graphql("schedule_items", [item])) is None
    good = schedule_item("si-2", "FREQ=WEEKLY;INTERVAL=2;BYDAY=TU")
    assert value(SCHEDULED, graphql("schedule_items", [item, good])) is True


# ---------------------------------------------------------------------------------------------- isDASTScanCurrent

CURRENT = "isDASTScanCurrent"


def test_the_newest_successful_scan_decides_even_out_of_order():
    out = run(CURRENT, graphql("scans", [completed("s1", "101", 50), completed("s2", "102", 4)]))
    assert out["transformedResponse"][CURRENT] is True
    assert out["transformedResponse"]["daysSinceLastScan"] == 4
    assert "app-102.example.test" in out["additionalInfo"]["evaluation"]["passReasons"][0]


def test_thirty_days_is_still_current_and_thirty_one_is_not():
    assert value(CURRENT, graphql("scans", [completed("s1", "101", 30)])) is True
    out = run(CURRENT, graphql("scans", [completed("s1", "101", 31)]))
    assert out["transformedResponse"][CURRENT] is False
    assert out["transformedResponse"]["daysSinceLastScan"] == 31


def test_no_successful_scan_fails():
    out = run(CURRENT, graphql("scans", []))
    assert out["transformedResponse"][CURRENT] is False
    assert "no successful scan" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_scan_of_another_status_without_a_recent_success_is_not_evaluated():
    body = graphql("scans", [completed("s1", "101", 2, status="failed"), completed("s2", "101", 90)])
    assert value(CURRENT, body) is None


def test_an_unreadable_end_time_without_a_recent_success_is_not_evaluated():
    scan = dict(completed("s1", "101", 2), end_time=None)
    assert value(CURRENT, graphql("scans", [scan])) is None
    assert value(CURRENT, graphql("scans", [scan, completed("s2", "102", 5)])) is True


# ---------------------------------------------------------------------------------------------- issue counts

HIGH = "dastHighSeverityIssuesCount"
MEDIUM = "dastMediumSeverityIssuesCount"


def test_each_target_counts_once_from_its_newest_successful_scan():
    scans = [completed("s3", "101", 2, high=1, medium=0), completed("s2", "102", 5, high=2, medium=7),
             completed("s1", "101", 20, high=5, medium=9)]
    out = run(HIGH, graphql("scans", scans))
    assert out["transformedResponse"][HIGH] == 3
    assert out["transformedResponse"]["scanTargetsAssessed"] == 2
    reasons = out["additionalInfo"]["evaluation"]["failReasons"]
    assert "'app-102.example.test': 2 " in reasons[1]
    assert value(MEDIUM, graphql("scans", scans)) == 7


def test_a_clean_latest_scan_overrides_an_older_dirty_one():
    scans = [completed("s1", "101", 30, high=4), completed("s2", "101", 1, high=0)]
    out = run(HIGH, graphql("scans", scans))
    assert out["transformedResponse"][HIGH] == 0
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("key", [HIGH, MEDIUM])
def test_no_successful_scan_is_not_measured_never_zero(key):
    out = run(key, graphql("scans", []))
    assert out["transformedResponse"][key] is None
    assert collection(out) == "error"


@pytest.mark.parametrize("key", [HIGH, MEDIUM])
def test_a_full_page_could_miss_a_target_so_it_is_not_measured(key):
    scans = [completed("s" + str(n), str(n), 1) for n in range(100)]
    assert value(key, graphql("scans", scans)) is None
    assert value(key, graphql("scans", scans[:99])) == 0


@pytest.mark.parametrize("key", [HIGH, MEDIUM])
@pytest.mark.parametrize("mutate", [
    lambda s: s.pop("issue_counts"),
    lambda s: s["issue_counts"].pop("high") and s["issue_counts"].pop("medium"),
    lambda s: s["issue_counts"]["high"].update(total=True) or s["issue_counts"]["medium"].update(total=None),
    lambda s: s["issue_counts"]["high"].update(total=-1) or s["issue_counts"]["medium"].update(total="2"),
    lambda s: s.update(scan_target=None),
    lambda s: s["scan_target"].update(id=""),
    lambda s: s.update(end_time="yesterday"),
    lambda s: s.update(status="failed"),
], ids=["no-issue-counts", "no-band", "bool-or-null-total", "negative-or-text-total", "no-target", "blank-target-id",
        "unreadable-end", "not-succeeded"])
def test_an_unreadable_scan_is_not_evaluated(key, mutate):
    scan = completed("s1", "101", 2, high=1, medium=1)
    mutate(scan)
    assert value(key, graphql("scans", [completed("s2", "102", 3), scan])) is None


# ---------------------------------------------------------------------------------------------- failed scan targets

FAILED = "failedDASTScanTargetsCount"


def test_only_the_latest_finished_scan_of_each_target_decides():
    scans = [
        recent("s6", "104", 0, "running"),
        recent("s5", "101", 1, "failed", "Unable to reach the site start URL"),
        recent("s4", "102", 2, "succeeded"),
        recent("s3", "103", 3, "cancelled"),
        recent("s2", "102", 9, "failed", "Agent lost"),
        recent("s1", "101", 10, "succeeded"),
    ]
    out = run(FAILED, graphql("scans", scans))
    assert out["transformedResponse"][FAILED] == 1
    assert out["transformedResponse"]["scanTargetsAssessed"] == 3
    reasons = out["additionalInfo"]["evaluation"]["failReasons"]
    assert "app-101.example.test" in reasons[1] and "Unable to reach the site start URL" in reasons[1]
    assert "app-103.example.test" in out["additionalInfo"]["evaluation"]["additionalFindings"][0]


def test_every_target_passing_its_latest_scan_is_zero():
    scans = [recent("s2", "101", 1, "succeeded"), recent("s1", "101", 5, "failed", "Agent lost")]
    out = run(FAILED, graphql("scans", scans))
    assert out["transformedResponse"][FAILED] == 0
    assert out["additionalInfo"]["evaluation"]["passReasons"]


def test_no_finished_scan_is_not_measured():
    assert value(FAILED, graphql("scans", [recent("s1", "101", 0, "queued"), recent("s2", "102", 0, "paused")])) is None
    assert value(FAILED, graphql("scans", [])) is None


def test_a_full_page_is_not_measured():
    scans = [recent("s" + str(n), str(n), 1, "succeeded") for n in range(100)]
    assert value(FAILED, graphql("scans", scans)) is None
    assert value(FAILED, graphql("scans", scans[:99])) == 0


@pytest.mark.parametrize("scan", [
    dict(recent("s1", "101", 1, "succeeded"), status="exploded"),
    dict(recent("s1", "101", 1, "failed"), scan_target={"name": "no id"}),
    dict(recent("s1", "101", 1, "succeeded"), start_time=None),
], ids=["unknown-status", "no-target-id", "no-start-time"])
def test_an_unreadable_scan_is_not_evaluated_for_failures(scan):
    assert value(FAILED, graphql("scans", [recent("s2", "102", 0, "succeeded"), scan])) is None
