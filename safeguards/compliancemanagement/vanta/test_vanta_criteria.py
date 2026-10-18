"""Vanta people criteria: third-party proof (level 3) read from Vanta task statuses.

The contract these tests pin:
- a rate or count is a number only when the read was proven complete, every entry was readable, every status
  was one this file knows and there was a population to count; any other body is None AND
  dataCollection.status "error" (shown as Not evaluated), never 0 and never a failed check;
- a real zero is told apart from a parse that found nothing: the denominator comes back beside the value
  (peopleApplicable and the like), and a body that holds records but yields no readable population is None;
- people who are not current employees, people the task is disabled for and unassigned tasks are left out of a
  rate and reported;
- the vendor's own error text never reaches the result.

Every payload is synthetic (made-up ids, no real person, no real company).
"""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL = "planted-vendor-text-9c21"

RATES = {
    "backgroundcheckcompletionrate": ("backgroundCheckCompletionRate", "backgroundCheck"),
    "policyacknowledgmentcompletionrate": ("policyAcknowledgmentCompletionRate", "policy"),
    "trainingassignmentcompletionrate": ("trainingAssignmentCompletionRate", "training"),
    "devicemonitoringinstallcompletionrate": ("deviceMonitoringInstallCompletionRate", "deviceMonitoring"),
}


def load(name):
    spec = importlib.util.spec_from_file_location("vanta_" + name, HERE / (name + ".py"))
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


def people(items, **kw):
    return body("vantaPeople", items, "people", **kw)


def person(employment="CURRENT", **fields):
    record = {"employmentStatus": employment, "tasksStatus": "COMPLETE"}
    record.update(fields)
    return record


def value(module, key, data):
    return module.transform(data)["transformedResponse"][key]


def assert_not_measured(out, key):
    assert out["transformedResponse"] == {key: None}, out["transformedResponse"]
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error" and collection["errors"]


# ------------------------------------------------------------------------------------------ task rates

def test_rate_counts_current_employees_and_reports_the_denominator():
    for file, (key, flat) in RATES.items():
        module = load(file)
        rows = [person(**{flat + "Status": "COMPLETE"}) for _ in range(3)]
        rows.append(person(**{flat + "Status": "OVERDUE"}))
        out = module.transform(people(rows))
        assert out["transformedResponse"][key] == 75.0, file
        assert out["transformedResponse"]["peopleApplicable"] == 4
        assert out["transformedResponse"]["peopleComplete"] == 3
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"
        assert out["additionalInfo"]["metadata"]["proofLevel"] == 3


def test_a_real_zero_is_a_zero_with_its_denominator():
    for file, (key, flat) in RATES.items():
        module = load(file)
        rows = [person(**{flat + "Status": "OVERDUE"}), person(**{flat + "Status": "DUE_SOON"})]
        out = module.transform(people(rows))
        assert out["transformedResponse"][key] == 0.0
        assert out["transformedResponse"]["peopleApplicable"] == 2


def test_people_who_are_not_current_exempt_or_unassigned_are_left_out_and_reported():
    module = load("backgroundcheckcompletionrate")
    rows = [
        person(backgroundCheckStatus="COMPLETE"),
        person("ON_LEAVE", backgroundCheckStatus="OVERDUE"),
        person("FORMER", backgroundCheckStatus="OVERDUE"),
        person("INACTIVE", backgroundCheckStatus="OVERDUE"),
        person("UPCOMING", backgroundCheckStatus="NONE"),
        person(backgroundCheckStatus="OVERDUE", backgroundCheckDisabledOn="2026-01-02T00:00:00Z"),
        person(backgroundCheckStatus="NONE"),
    ]
    out = module.transform(people(rows))
    assert out["transformedResponse"]["backgroundCheckCompletionRate"] == 50.0
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["peopleApplicable"] == 2 and summary["exempt"] == 1 and summary["unassigned"] == 1
    assert summary["notCurrentEmployees"] == 3 and summary["peopleRead"] == 7


def test_records_that_yield_no_population_are_not_a_zero():
    """The failure this file exists to prevent: 20 records, a parse that found nothing, a rate of 0."""
    for file, (key, flat) in RATES.items():
        module = load(file)
        nothing_found = [{"id": "x%d" % i, "somethingElse": {"status": "COMPLETE"}} for i in range(20)]
        assert_not_measured(module.transform(people(nothing_found)), key)
        no_task = [person() for _ in range(20)]  # current employees, task status absent from the projection
        for row in no_task:
            del row["tasksStatus"]
        assert_not_measured(module.transform(people(no_task)), key)
        everyone_unassigned = [person(**{flat + "Status": "NONE"}) for _ in range(5)]
        assert_not_measured(module.transform(people(everyone_unassigned)), key)
        only_former = [person("FORMER", **{flat + "Status": "COMPLETE"}) for _ in range(5)]
        assert_not_measured(module.transform(people(only_former)), key)


def test_an_unrecognised_status_is_not_evaluated():
    module = load("trainingassignmentcompletionrate")
    key = "trainingAssignmentCompletionRate"
    assert_not_measured(module.transform(people([person(trainingStatus="COMPLETE"), person(trainingStatus="SOMETHING_NEW")])), key)
    assert_not_measured(module.transform(people([person("PARTIAL", trainingStatus="COMPLETE")])), key)
    assert_not_measured(module.transform(people([person(trainingStatus="COMPLETE"), "not a record"])), key)


def test_a_read_that_is_not_proven_complete_is_not_evaluated():
    module = load("policyacknowledgmentcompletionrate")
    key = "policyAcknowledgmentCompletionRate"
    rows = [person(policyStatus="COMPLETE")]
    assert_not_measured(module.transform(people(rows, complete=False)), key)
    assert_not_measured(module.transform(people(rows, complete=None)), key)
    assert_not_measured(module.transform(people(rows, truncated=True)), key)
    assert value(module, key, people(rows)) == 100.0


def test_error_empty_and_unrecognised_bodies_are_not_evaluated():
    for file, (key, flat) in RATES.items():
        module = load(file)
        for data in [{}, None, "", "{}", [], {"hello": "world"}, {"vantaPeople": "x"}, {"vantaPeople": {"people": "x"}},
                     {"error": True, "message": SENTINEL}, {"statusCode": 401, "message": SENTINEL},
                     {"apiResponse": {"errors": [SENTINEL]}}, b"\xff\xfe"]:
            out = module.transform(data)
            assert_not_measured(out, key)
            assert SENTINEL not in json.dumps(out)


def test_wrappers_strings_and_the_unprojected_vanta_shape_all_read():
    module = load("backgroundcheckcompletionrate")
    key = "backgroundCheckCompletionRate"
    flat = people([person(backgroundCheckStatus="COMPLETE"), person(backgroundCheckStatus="OVERDUE")])
    assert value(module, key, json.dumps(flat)) == 50.0
    assert value(module, key, {"apiResponse": flat}) == 50.0
    assert value(module, key, json.dumps({"response": {"data": flat}})) == 50.0
    raw = {"employment": {"status": "CURRENT"},
           "tasksSummary": {"status": "COMPLETE", "details": {"completeBackgroundChecks": {"status": "COMPLETE", "disabled": None}}}}
    raw2 = json.loads(json.dumps(raw))
    raw2["tasksSummary"]["details"]["completeBackgroundChecks"]["status"] = "OVERDUE"
    assert value(module, key, people([raw, raw2])) == 50.0


# ------------------------------------------------------------------------------------------ offboarding

def test_offboarding_rate_and_overdue_count():
    rate = load("offboardingcompletionrate")
    count = load("overdueoffboardingcount")
    rows = [person(tasksStatus="OFFBOARDING_COMPLETE"), person(tasksStatus="OFFBOARDING_COMPLETE"),
            person(tasksStatus="OFFBOARDING_OVERDUE"), person(tasksStatus="OFFBOARDING_DUE_SOON"),
            person(tasksStatus="COMPLETE"), person(tasksStatus="PAUSED")]
    out = rate.transform(people(rows))
    assert out["transformedResponse"]["offboardingCompletionRate"] == 50.0
    assert out["transformedResponse"]["peopleInOffboarding"] == 4
    out = count.transform(people(rows))
    assert out["transformedResponse"]["overdueOffboardingCount"] == 1
    assert out["transformedResponse"]["peopleRead"] == 6


def test_offboarding_zero_overdue_is_a_real_zero_but_nobody_in_offboarding_is_no_rate():
    rate = load("offboardingcompletionrate")
    count = load("overdueoffboardingcount")
    stayers = [person(tasksStatus="COMPLETE"), person(tasksStatus="DUE_SOON")]
    out = count.transform(people(stayers))
    assert out["transformedResponse"]["overdueOffboardingCount"] == 0 and out["transformedResponse"]["peopleRead"] == 2
    assert_not_measured(rate.transform(people(stayers)), "offboardingCompletionRate")
    assert_not_measured(count.transform(people([])), "overdueOffboardingCount")


def test_offboarding_unknown_status_incomplete_read_and_errors_are_not_evaluated():
    for file, key in (("offboardingcompletionrate", "offboardingCompletionRate"),
                      ("overdueoffboardingcount", "overdueOffboardingCount")):
        module = load(file)
        assert_not_measured(module.transform(people([person(tasksStatus="OFFBOARDING_COMPLETE"), person(tasksStatus="LATER")])), key)
        assert_not_measured(module.transform(people([person(tasksStatus="OFFBOARDING_COMPLETE")], complete=False)), key)
        assert_not_measured(module.transform(people([{"id": "x"}])), key)
        out = module.transform({"error": SENTINEL})
        assert_not_measured(out, key)
        assert SENTINEL not in json.dumps(out)
