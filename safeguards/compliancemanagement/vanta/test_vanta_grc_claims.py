"""Vanta test results are third-party proof (level 3): a failing control reads False, anything unproven reads None.

Vanta is a proof source, not a safeguard tool. These four transforms judge the tests Vanta reports for
one criterion each (MFA, account lifecycle, patching, role-based access). They never fetch, and they
never read the tool itself: Spektrum's own read of a tool (level 4) always wins over what is decided here.

The contract these tests pin:
- every mapped test OK and the read proven complete -> True;
- any mapped test NEEDS_ATTENTION -> False, even when the read was cut short (a failure already seen is a failure);
- every other body (error, empty, unrecognised, nothing mapped, an unclear test, an unreadable entry, a read that
  is not proven complete) -> None AND dataCollection.status "error", so the evaluator shows Not evaluated and a
  transient failure never becomes a failed control;
- a test is mapped by whole words, so "patchwork" is not a patch test;
- NOT_APPLICABLE is left out of the answer; DEACTIVATED, IN_PROGRESS, INVALID and unknown statuses never pass
  and never fail;
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
SENTINEL = "planted-vendor-text-4d7a"

CHECKS = {
    "isstrongauthrequired": "isStrongAuthRequired",
    "islifecyclemanagementenabled": "isLifeCycleManagementEnabled",
    "ispatchmanagementenabled": "isPatchManagementEnabled",
    "isrbacimplemented": "isRBACImplemented",
}
#: two synthetic tests per criterion that the groups must map
MAPPED = {
    "isStrongAuthRequired": [("mfa-enabled-on-identity-provider-accounts", "MFA is enabled on identity provider accounts"),
                             ("mfa-enforced-on-cloud-console", "Multi-factor authentication is enforced on the cloud console")],
    "isLifeCycleManagementEnabled": [("access-removed-on-termination", "Access is removed when an employee is terminated"),
                                     ("offboarding-accounts-deprovisioned", "Offboarded users are deprovisioned")],
    "isPatchManagementEnabled": [("operating-system-patches-applied", "Operating system patches are applied"),
                                 ("servers-patched-within-policy", "Servers are patched within the policy window")],
    "isRBACImplemented": [("rbac-enforced-on-cloud-accounts", "RBAC is enforced on cloud accounts"),
                          ("least-privilege-for-production-access", "Production access follows least privilege")],
}
UNRELATED = ("encryption-at-rest-enabled", "Data is encrypted at rest")
#: contains no whole word the groups look for (patchwork, rbacs, mfas, terminatedx are other words)
DECOY = ("patchwork-rbacs-mfas-terminatedx", "Patchwork and rbacs and mfas and terminatedx")
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}


def load(name):
    spec = importlib.util.spec_from_file_location("vanta_claim_" + name, HERE / (name + ".py"))
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


#: the people criteria that sit beside the four claim files (test_vanta_criteria.py)
MEASURED = {"backgroundcheckcompletionrate", "policyacknowledgmentcompletionrate", "trainingassignmentcompletionrate",
            "devicemonitoringinstallcompletionrate", "offboardingcompletionrate", "overdueoffboardingcount"}


def test_one_file_per_criterion():
    on_disk = {p.stem for p in HERE.glob("*.py") if not p.stem.startswith("test_")}
    assert on_disk == set(CHECKS) | MEASURED


def vt(pair, status="OK"):
    test = {"id": pair[0], "name": pair[1], "category": "ACCOUNT_SECURITY"}
    if status is not None:
        test["status"] = status
    return test


def body(tests, truncated=False, marker=True):
    """The getVantaTestResults workflow output, as Integration-Service builds it."""
    out = {"vantaTests": {"tests": tests}}
    if truncated:
        out["vantaTests"]["truncated"] = True
        out["paginationTruncated"] = True
    if marker:
        out["paginationStats"] = {"vantaTests": {"paginationTruncated": bool(truncated)}}
    return out


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


def test_every_mapped_test_ok_and_complete_is_true(check):
    name, key = check
    tests = [vt(p) for p in MAPPED[key]] + [vt(UNRELATED)]
    value, result = run(name, body(tests))
    assert value is True
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"
    assert result["additionalInfo"]["evaluation"]["failReasons"] == []


def test_one_failing_mapped_test_is_false(check):
    name, key = check
    tests = [vt(MAPPED[key][0]), vt(MAPPED[key][1], "NEEDS_ATTENTION")]
    value, result = run(name, body(tests))
    assert value is False
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"
    assert result["additionalInfo"]["evaluation"]["failReasons"]


def test_a_failure_already_seen_counts_in_a_cut_short_read(check):
    name, key = check
    tests = [vt(MAPPED[key][0], "NEEDS_ATTENTION")]
    assert run(name, body(tests, truncated=True))[0] is False
    assert run(name, body(tests, marker=False))[0] is False


def test_a_pass_in_a_read_that_is_not_proven_complete_is_none(check):
    name, key = check
    tests = [vt(p) for p in MAPPED[key]]
    assert_not_evaluated(*run(name, body(tests, truncated=True)))
    # a build that does not report paging at all is not proof of a complete read
    assert_not_evaluated(*run(name, body(tests, marker=False)))
    missing_flag = body(tests)
    missing_flag["paginationStats"]["vantaTests"] = {}
    assert_not_evaluated(*run(name, missing_flag))
    assert_not_evaluated(*run(name, {"vantaTests": {"tests": tests}, "paginationStats": {"other": {"paginationTruncated": False}}}))


@pytest.mark.parametrize("status", ["DEACTIVATED", "IN_PROGRESS", "INVALID", "SOMETHING_NEW", "", None, 7])
def test_an_unclear_mapped_test_is_none_never_false(check, status):
    name, key = check
    tests = [vt(MAPPED[key][0]), vt(MAPPED[key][1], status)]
    assert_not_evaluated(*run(name, body(tests)))
    # on its own it is no better
    assert_not_evaluated(*run(name, body([vt(MAPPED[key][0], status)])))


def test_an_unclear_test_does_not_hide_a_failure(check):
    name, key = check
    tests = [vt(MAPPED[key][0], "DEACTIVATED"), vt(MAPPED[key][1], "NEEDS_ATTENTION")]
    assert run(name, body(tests))[0] is False


def test_not_applicable_is_left_out_of_the_answer(check):
    name, key = check
    tests = [vt(MAPPED[key][0]), vt(MAPPED[key][1], "NOT_APPLICABLE")]
    assert run(name, body(tests))[0] is True
    assert_not_evaluated(*run(name, body([vt(MAPPED[key][0], "NOT_APPLICABLE")])))


def test_status_case_and_spacing_are_ignored(check):
    name, key = check
    assert run(name, body([vt(MAPPED[key][0], " ok ")]))[0] is True
    assert run(name, body([vt(MAPPED[key][0], "needs_attention")]))[0] is False


def test_nothing_mapped_is_none(check):
    name, key = check
    assert_not_evaluated(*run(name, body([vt(UNRELATED)])))
    assert_not_evaluated(*run(name, body([])))


def test_a_failing_test_for_another_control_does_not_change_the_answer(check):
    name, key = check
    tests = [vt(MAPPED[key][0]), vt(UNRELATED, "NEEDS_ATTENTION")]
    for other, pairs in MAPPED.items():
        if other != key:
            tests.append(vt(pairs[0], "NEEDS_ATTENTION"))
    assert run(name, body(tests))[0] is True


def test_a_test_is_mapped_by_whole_words_only(check):
    name, key = check
    assert_not_evaluated(*run(name, body([vt(DECOY, "NEEDS_ATTENTION")])))
    assert_not_evaluated(*run(name, body([vt(DECOY, "OK")])))


def test_a_mapped_name_is_found_in_the_id_or_the_name(check):
    name, key = check
    only_id = {"id": MAPPED[key][0][0], "name": "Unrelated title", "status": "NEEDS_ATTENTION"}
    only_name = {"id": "unrelated-slug", "name": MAPPED[key][0][1], "status": "NEEDS_ATTENTION"}
    assert run(name, body([only_id]))[0] is False
    assert run(name, body([only_name]))[0] is False


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
    {"vantaTests": {}},
    {"vantaTests": {"tests": None}},
    {"vantaTests": {"tests": "nope"}},
    {"vantaTests": []},
    # an error marker around a list that looks like a full pass proves nothing
    {"error": True, "message": SENTINEL, "vantaTests": {"tests": [{"id": "mfa-x", "name": "MFA", "status": "OK"}]},
     "paginationStats": {"vantaTests": {"paginationTruncated": False}}},
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
    good = [vt(p) for p in MAPPED[key]]
    assert_not_evaluated(*run(name, body(good + ["garbage"])))
    assert_not_evaluated(*run(name, body(good + [None, 5])))
    # a failure already seen keeps its verdict
    assert run(name, body([vt(MAPPED[key][0], "NEEDS_ATTENTION"), "garbage"]))[0] is False


def test_the_same_answer_from_a_string_and_from_the_wrappers(check):
    name, key = check
    passing = body([vt(p) for p in MAPPED[key]])
    failing = body([vt(MAPPED[key][0]), vt(MAPPED[key][1], "NEEDS_ATTENTION")])
    for source, expected in ((passing, True), (failing, False)):
        assert run(name, json.dumps(source))[0] is expected
        assert run(name, json.dumps(source).encode("utf-8"))[0] is expected
        assert run(name, {"data": source, "validation": VALIDATION})[0] is expected
        assert run(name, {"apiResponse": source})[0] is expected
        assert run(name, {"apiResponse": json.dumps(source)})[0] is expected
        assert run(name, {"data": {"apiResponse": source}, "validation": VALIDATION})[0] is expected


def test_the_result_says_where_the_answer_came_from(check):
    name, key = check
    result = run(name, body([vt(p) for p in MAPPED[key]]))[1]
    meta = result["additionalInfo"]["metadata"]
    assert meta["vendor"] == "Vanta"
    assert meta["method"] == "getVantaTestResults"
    assert meta["proofSource"] == "third_party_claim"
    assert meta["proofLevel"] == 3
    assert meta["transformationId"] == key
    assert "Spektrum has not read the tool itself" in " ".join(result["additionalInfo"]["evaluation"]["passReasons"])


def test_the_summary_carries_ids_and_outcomes_but_no_free_text(check):
    name, key = check
    noisy = vt(MAPPED[key][0])
    noisy["description"] = SENTINEL
    noisy["owner"] = {"emailAddress": SENTINEL}
    summary = run(name, body([noisy, vt(MAPPED[key][1], "NEEDS_ATTENTION")]))[1]["additionalInfo"]["transformation"]["inputSummary"]
    assert SENTINEL not in json.dumps(summary)
    assert summary["mappedTests"] == 2 and summary["passing"] == 1 and summary["failing"] == 1
    assert {m["outcome"] for m in summary["matchedTests"]} == {"pass", "fail"}
