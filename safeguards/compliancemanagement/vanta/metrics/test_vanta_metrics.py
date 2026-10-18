"""Vanta programme metrics: control readiness and the failing and overdue test counts.

These figures are read on demand through the API and the MCP server. They are not criteria on any requirement.
The contract these tests pin:
- a rate or count is a number only when the read was proven complete, every entry was readable, every status
  was one this file knows and there was a population to count; any other body is None AND
  dataCollection.status "error" (shown as Not evaluated), never 0 and never a failed check;
- a real zero is told apart from a parse that found nothing: the denominator comes back beside the value;
- the vendor's own error text never reaches the result.

Every payload is synthetic (made-up ids, no real person, no real company).
"""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL = "planted-vendor-text-9c21"


def load(name):
    spec = importlib.util.spec_from_file_location("vanta_metric_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body(key, items, listname, truncated=False, complete=True):
    """The workflow output Integration-Service hands the transform."""
    out = {key: {listname: items, "truncated": truncated}}
    out["paginationStats"] = {key: {"paginationTruncated": (not complete) if complete is not None else None}}
    if complete is None:
        out["paginationStats"] = {}
    return out


def value(module, key, data):
    return module.transform(data)["transformedResponse"][key]


def assert_not_measured(out, key):
    assert out["transformedResponse"] == {key: None}, out["transformedResponse"]
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error" and collection["errors"]


# ------------------------------------------------------------------------------------------ tests and frameworks

def vtests(items, **kw):
    return body("vantaTests", items, "tests", **kw)


def vtest(status="OK", remediation="PASS"):
    return {"id": "t", "name": "n", "status": status, "remediationStatus": remediation}


def test_failing_tests_count_and_overdue_remediation_count():
    failing = load("failingmonitoringtestscount")
    overdue = load("overduetestremediationcount")
    rows = [vtest(), vtest("NEEDS_ATTENTION", "OVERDUE"), vtest("NEEDS_ATTENTION", "DUE_SOON"),
            vtest("DEACTIVATED", "DISABLED"), vtest("NOT_APPLICABLE", "NA")]
    out = failing.transform(vtests(rows))
    assert out["transformedResponse"]["failingMonitoringTestsCount"] == 2
    assert out["transformedResponse"]["testsRead"] == 5
    assert overdue.transform(vtests(rows))["transformedResponse"]["overdueTestRemediationCount"] == 1
    clean = vtests([vtest(), vtest()])
    assert value(failing, "failingMonitoringTestsCount", clean) == 0
    assert value(overdue, "overdueTestRemediationCount", clean) == 0


def test_test_counts_are_not_evaluated_when_unreadable_unknown_or_cut_short():
    for file, key in (("failingmonitoringtestscount", "failingMonitoringTestsCount"),
                      ("overduetestremediationcount", "overdueTestRemediationCount")):
        module = load(file)
        assert_not_measured(module.transform(vtests([vtest(), vtest("MYSTERY")])), key)
        assert_not_measured(module.transform(vtests([vtest(), "x"])), key)
        assert_not_measured(module.transform(vtests([vtest()], complete=False)), key)
        assert_not_measured(module.transform(vtests([])), key)
        assert_not_measured(module.transform({"error": SENTINEL}), key)
    # the remediation count also needs a readable remediation status; the failing count does not
    missing = [{"id": "t", "status": "OK"}]
    assert_not_measured(load("overduetestremediationcount").transform(vtests(missing)), "overdueTestRemediationCount")
    assert value(load("failingmonitoringtestscount"), "failingMonitoringTestsCount", vtests(missing)) == 0


def frameworks(items, **kw):
    return body("vantaFrameworks", items, "frameworks", **kw)


def fw(done, total, status="ACTIVE"):
    return {"id": "f", "displayName": "F", "numControlsCompleted": done, "numControlsTotal": total, "status": status}


def test_control_readiness_sums_active_frameworks_only():
    module = load("controlreadinesspercentage")
    key = "controlReadinessPercentage"
    out = module.transform(frameworks([fw(63, 81), fw(10, 10), fw(0, 50, "ARCHIVED")]))
    assert out["transformedResponse"][key] == round(100.0 * 73 / 91, 2)
    assert out["transformedResponse"]["controlsTotal"] == 91
    assert value(module, key, frameworks([fw(0, 20)])) == 0.0


def test_control_readiness_is_not_evaluated_on_a_status_it_does_not_know():
    module = load("controlreadinesspercentage")
    key = "controlReadinessPercentage"
    # an unknown status beside an ACTIVE one must not read as a confident 100
    assert_not_measured(module.transform(frameworks([fw(10, 10), fw(0, 80, "ENABLED")])), key)
    assert_not_measured(module.transform(frameworks([fw(10, 10), fw(0, 80, "MYSTERY")])), key)
    # the statuses Vanta documents as inactive are left out, with no error
    out = module.transform(frameworks([fw(10, 10), fw(0, 80, "DRAFT"), fw(0, 5, "SNOOZED"),
                                       fw(0, 5, "ARCHIVED"), fw(0, 5, "NEW_UPGRADE")]))
    assert out["transformedResponse"][key] == 100.0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_control_readiness_is_not_evaluated_without_a_readable_population():
    module = load("controlreadinesspercentage")
    key = "controlReadinessPercentage"
    for data in [frameworks([]), frameworks([fw(1, 2, "ARCHIVED")]), frameworks([fw(0, 0)]), frameworks([fw(5, 3)]),
                 frameworks([fw(True, 4)]), frameworks([{"id": "f"}]), frameworks([fw(1, 2)], complete=False),
                 {"error": SENTINEL}, {}]:
        assert_not_measured(module.transform(data), key)
