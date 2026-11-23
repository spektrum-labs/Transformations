"""Drata monitoring-test results are third-party proof (level 3): a failing control reads False, anything unproven reads None.

UNPROVEN: written from Drata's published API reference only; there is no Drata account to read. The shapes below
are what the Integration-Service workflow getDrataTestResults is built to produce, not a recording of a real answer.

Drata is a proof source, not a safeguard tool. These four transforms judge the monitoring tests Drata reports for
one criterion each (MFA, account lifecycle, patching, role-based access). They never fetch, and they never read
the tool itself: Spektrum's own read of a tool (level 4) always wins over what is decided here.

The contract these tests pin:
- every mapped test enabled and PASSED, in every workspace, with the read proven complete -> True;
- any mapped enabled test FAILED -> False, even when the read was cut short (a failure already seen is a failure);
- every other body (error, empty, unrecognised, nothing mapped, a test that is not enabled or has no result yet,
  a workspace that failed, a read not proven complete) -> None AND dataCollection.status "error", so the
  evaluator shows Not evaluated and a transient failure never becomes a failed control;
- a test is mapped by whole words in its name, so "patchwork" is not a patch test;
- the vendor's own error text never reaches the result.

Every payload is synthetic. Stored raw responses are stringified, so each verdict is also run from a JSON string
and from the Integration-Service wrappers.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent

#: planted in every error body; it must never come back out in the result
SENTINEL = "planted-vendor-text-b83e"

CHECKS = {
    "isstrongauthrequired": "isStrongAuthRequired",
    "islifecyclemanagementenabled": "isLifeCycleManagementEnabled",
    "ispatchmanagementenabled": "isPatchManagementEnabled",
    "isrbacimplemented": "isRBACImplemented",
}
#: two synthetic test names per criterion that the groups must map
MAPPED = {
    "isStrongAuthRequired": ["MFA is enabled on identity provider accounts",
                             "Multi-factor authentication is enforced on the cloud console"],
    "isLifeCycleManagementEnabled": ["Access is removed when an employee is terminated",
                                     "Offboarded users are deprovisioned"],
    "isPatchManagementEnabled": ["Operating system patches are applied",
                                 "Servers are patched within the policy window"],
    "isRBACImplemented": ["RBAC is enforced on cloud accounts",
                          "Production access follows least privilege"],
}
UNRELATED = "Data is encrypted at rest"
#: contains no whole word the groups look for (patchwork, rbacs, mfas, terminatedx are other words)
DECOY = "Patchwork and rbacs and mfas and terminatedx"
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}
_ids = iter(range(1, 10000))


def load(name):
    spec = importlib.util.spec_from_file_location("drata_claim_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def test_one_file_per_criterion():
    on_disk = {p.stem for p in HERE.glob("*.py") if not p.stem.startswith("test_")}
    assert on_disk == set(CHECKS)


def dt(name, result="PASSED", state="ENABLED"):
    test = {"id": next(_ids), "name": name, "testId": next(_ids), "testSource": "DRATA"}
    if result is not None:
        test["checkResultStatus"] = result
    if state is not None:
        test["checkStatus"] = state
    return test


def body(*workspaces, ws_truncated=False, iterate_truncated=False, entry_truncated=False, marker=True,
         item_errors=0, total=None):
    """The getDrataTestResults workflow output: one entry per workspace, a list of tests or an item error record."""
    entries = []
    for ws in workspaces:
        if isinstance(ws, dict):
            entries.append(ws)
        else:
            entries.append({"tests": list(ws)})
    if entry_truncated:
        entries[0]["truncated"] = True
    out = {
        "drataWorkspaces": {"workspaces": [{"id": i + 1, "name": "workspace"} for i in range(len(workspaces))]},
        "drataTests": entries,
        "iterateStats": {"drataTests": {"itemsTotal": len(entries) if total is None else total,
                                        "itemsProcessed": len(entries), "itemErrors": item_errors,
                                        "iterateTruncated": iterate_truncated}},
        "itemErrors": item_errors,
    }
    if ws_truncated:
        out["drataWorkspaces"]["truncated"] = True
        out["paginationTruncated"] = True
    if iterate_truncated:
        out["iterateTruncated"] = True
    if marker:
        out["paginationStats"] = {"drataWorkspaces": {"paginationTruncated": bool(ws_truncated)}}
    return out


def item_error():
    return {"error": True, "statusCode": 500, "item": 2, "errorType": "vendor"}


def run(name, data):
    result = load(name).transform(data)
    return result["transformedResponse"][CHECKS[name]], result


def assert_not_evaluated(value, result):
    assert value is None
    info = result["additionalInfo"]
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"]
    assert SENTINEL not in json.dumps(result)


@pytest.fixture(params=sorted(CHECKS))
def check(request):
    return request.param, CHECKS[request.param]


def test_every_mapped_test_passing_in_every_workspace_and_complete_is_true(check):
    name, key = check
    first = [dt(MAPPED[key][0]), dt(UNRELATED, "FAILED")]
    second = [dt(MAPPED[key][1])]
    value, result = run(name, body(first, second))
    assert value is True
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"
    assert result["additionalInfo"]["evaluation"]["failReasons"] == []


def test_one_failing_enabled_test_in_any_workspace_is_false(check):
    name, key = check
    value, result = run(name, body([dt(MAPPED[key][0])], [dt(MAPPED[key][1], "FAILED")]))
    assert value is False
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"
    assert result["additionalInfo"]["evaluation"]["failReasons"]


def test_a_failure_already_seen_counts_in_a_cut_short_or_partial_read(check):
    name, key = check
    failing = [dt(MAPPED[key][0], "FAILED")]
    assert run(name, body(failing, ws_truncated=True))[0] is False
    assert run(name, body(failing, iterate_truncated=True))[0] is False
    assert run(name, body(failing, entry_truncated=True))[0] is False
    assert run(name, body(failing, marker=False))[0] is False
    assert run(name, body(failing, item_error(), item_errors=1))[0] is False


def test_a_pass_in_a_read_that_is_not_proven_complete_is_none(check):
    name, key = check
    passing = [dt(MAPPED[key][0]), dt(MAPPED[key][1])]
    assert_not_evaluated(*run(name, body(passing, ws_truncated=True)))
    assert_not_evaluated(*run(name, body(passing, iterate_truncated=True)))
    assert_not_evaluated(*run(name, body(passing, entry_truncated=True)))
    # a build that does not report paging at all is not proof of a complete read
    assert_not_evaluated(*run(name, body(passing, marker=False)))
    no_iterate_stats = body(passing)
    del no_iterate_stats["iterateStats"]
    assert_not_evaluated(*run(name, no_iterate_stats))
    # the fan-out did not cover every workspace
    assert_not_evaluated(*run(name, body(passing, total=2)))
    short = body(passing)
    short["drataWorkspaces"]["workspaces"].append({"id": 99, "name": "never read"})
    assert_not_evaluated(*run(name, short))


def test_a_workspace_that_failed_is_not_skipped(check):
    name, key = check
    passing = [dt(MAPPED[key][0]), dt(MAPPED[key][1])]
    assert_not_evaluated(*run(name, body(passing, item_error(), item_errors=1)))
    # an error record that the stats do not admit to is still never read as an empty workspace
    assert_not_evaluated(*run(name, body(passing, item_error())))
    assert_not_evaluated(*run(name, body(passing, {"tests": None})))
    assert_not_evaluated(*run(name, body(passing, "garbage")))


@pytest.mark.parametrize("state", ["DISABLED", "UNUSED", "NEW", "TESTING", "", None, 7])
def test_a_test_that_is_not_enabled_is_none_never_false(check, state):
    name, key = check
    assert_not_evaluated(*run(name, body([dt(MAPPED[key][0]), dt(MAPPED[key][1], "PASSED", state)])))
    # a failing result on a test that is not enabled proves nothing
    assert_not_evaluated(*run(name, body([dt(MAPPED[key][0], "FAILED", state)])))


@pytest.mark.parametrize("result_status", ["READY", "PREAUDIT", "ERROR", "SOMETHING_NEW", "", None, 7])
def test_a_test_without_a_clear_result_is_none_never_false(check, result_status):
    name, key = check
    assert_not_evaluated(*run(name, body([dt(MAPPED[key][0]), dt(MAPPED[key][1], result_status)])))
    assert_not_evaluated(*run(name, body([dt(MAPPED[key][0], result_status)])))


def test_an_unclear_test_does_not_hide_a_failure(check):
    name, key = check
    assert run(name, body([dt(MAPPED[key][0], "READY"), dt(MAPPED[key][1], "FAILED")]))[0] is False


def test_status_case_and_spacing_are_ignored(check):
    name, key = check
    assert run(name, body([dt(MAPPED[key][0], " passed ", "enabled")]))[0] is True
    assert run(name, body([dt(MAPPED[key][0], "failed", " Enabled ")]))[0] is False


def test_nothing_mapped_is_none(check):
    name, key = check
    assert_not_evaluated(*run(name, body([dt(UNRELATED)])))
    assert_not_evaluated(*run(name, body([])))
    assert_not_evaluated(*run(name, body()))


def test_a_failing_test_for_another_control_does_not_change_the_answer(check):
    name, key = check
    tests = [dt(MAPPED[key][0]), dt(UNRELATED, "FAILED")]
    for other, names in MAPPED.items():
        if other != key:
            tests.append(dt(names[0], "FAILED"))
    assert run(name, body(tests))[0] is True


def test_a_test_is_mapped_by_whole_words_in_the_name_only(check):
    name, key = check
    assert_not_evaluated(*run(name, body([dt(DECOY, "FAILED")])))
    assert_not_evaluated(*run(name, body([dt(DECOY)])))


ERROR_BODIES = [
    {},
    [],
    "",
    "not json at all",
    None,
    7,
    b"{}",
    {"error": True, "message": SENTINEL},
    {"error": SENTINEL},
    {"errors": [SENTINEL]},
    {"statusCode": 401, "message": SENTINEL},
    {"status": "403", "message": SENTINEL},
    {"status": 500, "message": SENTINEL},
    {"status_code": "429", "message": SENTINEL},
    {"apiResponse": {"error": True, "message": SENTINEL}},
    {"data": {"statusCode": 503, "message": SENTINEL}, "validation": VALIDATION},
    {"apiResponse": json.dumps({"error": SENTINEL})},
    {"message": SENTINEL},
    {"drataTests": {}},
    {"drataTests": None},
    {"drataTests": "nope"},
    {"drataWorkspaces": {"workspaces": []}},
    # an error marker around a list that looks like a full pass proves nothing
    dict(body([dt("MFA is enabled")]), error=True, message=SENTINEL),
    Poisoned(),
]


@pytest.mark.parametrize("data", ERROR_BODIES, ids=lambda d: type(d).__name__ + "-" + str(d)[:28])
def test_error_empty_and_unrecognised_bodies_are_not_evaluated(check, data):
    name, key = check
    value, result = run(name, data)
    assert_not_evaluated(value, result)
    assert list(result["transformedResponse"]) == [key]


def test_an_exception_text_goes_under_transformation_errors_only():
    value, result = run("isstrongauthrequired", Poisoned())
    info = result["additionalInfo"]
    assert info["transformation"]["status"] == "error"
    assert "poisoned read" in json.dumps(info["transformation"]["errors"])
    assert "poisoned read" not in json.dumps(info["dataCollection"])
    assert "poisoned read" not in json.dumps(info["evaluation"])


def test_an_entry_that_cannot_be_read_is_never_skipped(check):
    name, key = check
    good = [dt(MAPPED[key][0]), dt(MAPPED[key][1])]
    assert_not_evaluated(*run(name, body(good + ["garbage"])))
    assert_not_evaluated(*run(name, body(good + [None, 5])))
    assert run(name, body([dt(MAPPED[key][0], "FAILED"), "garbage"]))[0] is False


def test_the_same_answer_from_a_string_and_from_the_wrappers(check):
    name, key = check
    passing = body([dt(MAPPED[key][0]), dt(MAPPED[key][1])])
    failing = body([dt(MAPPED[key][0])], [dt(MAPPED[key][1], "FAILED")])
    for source, expected in ((passing, True), (failing, False)):
        assert run(name, json.dumps(source))[0] is expected
        assert run(name, json.dumps(source).encode("utf-8"))[0] is expected
        assert run(name, {"data": source, "validation": VALIDATION})[0] is expected
        assert run(name, {"apiResponse": source})[0] is expected
        assert run(name, {"apiResponse": json.dumps(source)})[0] is expected
        assert run(name, {"data": {"apiResponse": source}, "validation": VALIDATION})[0] is expected


def test_a_count_that_is_not_a_whole_number_is_not_proof_of_a_complete_read(check):
    name, key = check
    passing = [dt(MAPPED[key][0]), dt(MAPPED[key][1])]
    for bad in (True, "1", 1.0, None):
        source = body(passing)
        source["iterateStats"]["drataTests"]["itemsTotal"] = bad
        assert_not_evaluated(*run(name, source))
        source = body(passing)
        source["iterateStats"]["drataTests"]["itemErrors"] = bad
        assert_not_evaluated(*run(name, source))


def test_the_result_says_where_the_answer_came_from(check):
    name, key = check
    result = run(name, body([dt(MAPPED[key][0])]))[1]
    meta = result["additionalInfo"]["metadata"]
    assert meta["vendor"] == "Drata"
    assert meta["method"] == "getDrataTestResults"
    assert meta["proofSource"] == "third_party_claim"
    assert meta["proofLevel"] == 3
    assert meta["transformationId"] == key
    assert "Spektrum has not read the tool itself" in " ".join(result["additionalInfo"]["evaluation"]["passReasons"])


def test_the_summary_carries_ids_and_outcomes_but_no_free_text(check):
    name, key = check
    noisy = dt(MAPPED[key][0])
    noisy["description"] = SENTINEL
    noisy["owner"] = {"emailAddress": SENTINEL}
    summary = run(name, body([noisy, dt(MAPPED[key][1], "FAILED")]))[1]["additionalInfo"]["transformation"]["inputSummary"]
    assert SENTINEL not in json.dumps(summary)
    assert summary["mappedTests"] == 2 and summary["passing"] == 1 and summary["failing"] == 1
    assert {m["outcome"] for m in summary["matchedTests"]} == {"pass", "fail"}
