"""Wiz (Cloud Security): fail-closed checks over the GraphQL `issues` read.

Bodies are SYNTHETIC: Wiz's schema reference sits behind a login, so the shapes here are the ones the stored
getIssues query selects (issues { nodes { id severity status } pageInfo { hasNextPage endCursor } }) in the
GraphQL envelope {"data": {...}} that Integration-Service hands over, optionally wrapped, as a dict or a JSON
string. Error shapes (a GraphQL errors list, a statusCode, an error flag) are likewise made up. No customer data.

Rules under test: an error, GraphQL errors (even beside partial data), 401/403, an empty, unrecognised or
incomplete read (no pageInfo, more pages) or an unreadable issue is Not evaluated: the value is null and
additionalInfo.dataCollection.status is "error". Never 0, never False.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "criticalOpenFindingsCount"


def load():
    spec = importlib.util.spec_from_file_location("wiz_" + KEY, HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(body):
    return load().transform(copy.deepcopy(body))


def value(body):
    return result(body)["transformedResponse"][KEY]


def issue(i, severity="LOW", status="OPEN"):
    return {"id": "issue-" + str(i), "severity": severity, "status": status}


def read(nodes, has_next=False, cursor=None):
    return {"data": {"issues": {"nodes": nodes, "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}}}}


def not_evaluated(body):
    out = result(body)
    assert out["transformedResponse"] == {KEY: None}
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]
    return out


def test_counts_open_and_in_progress_critical_issues():
    nodes = [issue(1, "CRITICAL", "OPEN"), issue(2, "CRITICAL", "IN_PROGRESS"), issue(3, "CRITICAL", "OPEN"),
             issue(4, "HIGH", "OPEN"), issue(5, "LOW", "OPEN")]
    out = result(read(nodes))
    assert out["transformedResponse"] == {KEY: 3}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]
    assert out["additionalInfo"]["evaluation"]["recommendations"]


def test_resolved_and_rejected_critical_issues_are_not_open():
    nodes = [issue(1, "CRITICAL", "RESOLVED"), issue(2, "CRITICAL", "REJECTED"), issue(3, "CRITICAL", "OPEN")]
    assert value(read(nodes)) == 1


def test_no_critical_issue_among_other_severities_is_a_pass_of_zero():
    out = result(read([issue(1, "HIGH"), issue(2, "MEDIUM"), issue(3, "INFORMATIONAL")]))
    assert out["transformedResponse"] == {KEY: 0}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


def test_a_complete_read_with_no_issues_is_zero():
    assert value(read([])) == 0


def test_a_filtered_read_of_critical_open_issues_counts_every_node():
    assert value(read([issue(i, "CRITICAL", "OPEN") for i in range(7)])) == 7


def test_severity_and_status_are_matched_case_insensitively_and_trimmed():
    assert value(read([issue(1, " critical ", "open"), issue(2, "Critical", "In_Progress")])) == 2


def test_an_unfiltered_read_that_is_complete_is_judged_node_by_node():
    nodes = [issue(i, "CRITICAL", "RESOLVED") for i in range(40)] + [issue(99, "CRITICAL", "OPEN")]
    assert value(read(nodes)) == 1


def test_only_the_key_is_returned_so_no_second_criterion_leaks():
    assert list(result(read([issue(1, "CRITICAL")]))["transformedResponse"]) == [KEY]


@pytest.mark.parametrize("wrap", [
    lambda b: b,
    lambda b: {"apiResponse": b},
    lambda b: {"status": 200, "apiResponse": b},
    lambda b: {"response": {"result": b}},
    lambda b: {"apiResponse": json.dumps(b)},
    lambda b: json.dumps(b),
    lambda b: json.dumps({"apiResponse": b}),
    lambda b: b["data"],
])
def test_the_connection_is_found_under_any_wrapper(wrap):
    assert value(wrap(read([issue(1, "CRITICAL"), issue(2, "LOW")]))) == 1


def test_a_more_pages_read_is_not_evaluated_even_with_critical_issues_in_it():
    not_evaluated(read([issue(1, "CRITICAL")], has_next=True, cursor="abc"))


def test_a_more_pages_read_of_no_issues_is_not_evaluated():
    not_evaluated(read([], has_next=True, cursor="abc"))


@pytest.mark.parametrize("page", [None, {}, {"endCursor": "x"}, {"hasNextPage": None}, {"hasNextPage": "false"},
                                  {"hasNextPage": 0}, [], "x"])
def test_a_read_that_does_not_say_it_is_complete_is_not_evaluated(page):
    body = {"data": {"issues": {"nodes": [issue(1, "CRITICAL")], "pageInfo": page}}}
    if page is None:
        del body["data"]["issues"]["pageInfo"]
    not_evaluated(body)


@pytest.mark.parametrize("body", [
    {},
    None,
    "",
    "{}",
    "[]",
    "not json at all",
    [],
    [issue(1)],
    {"data": None},
    {"data": {}},
    {"data": {"issues": None}},
    {"data": {"issues": []}},
    {"data": {"issues": {}}},
    {"data": {"issues": {"nodes": None, "pageInfo": {"hasNextPage": False}}}},
    {"data": {"issues": {"nodes": "x", "pageInfo": {"hasNextPage": False}}}},
    {"data": {"issues": {"nodes": {"id": 1}, "pageInfo": {"hasNextPage": False}}}},
    {"apiResponse": {}},
    {"apiResponse": "{}"},
    {"apiResponse": None},
    {"unrelated": [1, 2, 3], "items": []},
    {"message": "Something went wrong"},
    {"detail": "Forbidden"},
    {"data": {"configurationFindings": {"nodes": [], "pageInfo": {"hasNextPage": False}}}},
])
def test_an_empty_or_unrecognised_body_is_not_evaluated(body):
    not_evaluated(body)


@pytest.mark.parametrize("body", [
    {"errors": [{"message": "Unauthorized"}], "data": None},
    {"errors": [{"message": "Field 'issues' argument 'filterBy' is invalid"}]},
    {"errors": ["rate limited"]},
    {"error": True, "statusCode": 401, "message": "Unauthorized"},
    {"error": True, "statusCode": 403, "message": "Forbidden"},
    {"error": "access denied"},
    {"statusCode": 403, "message": "Forbidden"},
    {"statusCode": 404, "message": "Not Found"},
    {"statusCode": 429, "message": "Too Many Requests"},
    {"statusCode": 500, "message": "Internal Server Error"},
    {"errorType": "AuthError", "message": "bad token"},
    {"status": 401, "apiResponse": {"message": "Unauthorized"}},
    {"status": False, "message": "refused"},
    {"apiResponse": {"statusCode": 403, "message": "Forbidden"}},
    {"apiResponse": {"errors": [{"message": "Unauthorized"}], "data": None}},
    {"apiResponse": json.dumps({"errors": [{"message": "Unauthorized"}]})},
])
def test_an_error_or_refused_answer_is_not_evaluated(body):
    not_evaluated(body)


def test_graphql_errors_beside_partial_data_are_not_evaluated():
    body = read([issue(1, "CRITICAL"), issue(2, "CRITICAL")])
    body["errors"] = [{"message": "partial failure"}]
    not_evaluated(body)


def test_an_error_next_to_the_connection_is_still_an_error():
    body = read([issue(1, "CRITICAL")])
    body.update({"statusCode": 403, "message": "Forbidden"})
    not_evaluated(body)


@pytest.mark.parametrize("bad", [
    {"id": "x"},
    {"id": "x", "severity": "CRITICAL"},
    {"id": "x", "status": "OPEN"},
    {"id": "x", "severity": None, "status": "OPEN"},
    {"id": "x", "severity": "CRITICAL", "status": None},
    {"id": "x", "severity": 5, "status": "OPEN"},
    {"id": "x", "severity": "CRITICAL", "status": True},
    {"id": "x", "severity": "", "status": "OPEN"},
    {"id": "x", "severity": "  ", "status": "OPEN"},
    "a string",
    None,
    7,
    [],
])
def test_one_unreadable_issue_makes_the_whole_count_not_evaluated(bad):
    not_evaluated(read([issue(1, "CRITICAL"), bad, issue(3, "LOW")]))


def test_a_value_is_never_false_or_a_bare_zero_when_nothing_was_measured():
    for body in ({}, None, "", {"statusCode": 403}, {"errors": [{"message": "x"}]}, read([], has_next=True)):
        assert result(body)["transformedResponse"][KEY] is None


def test_the_transform_does_not_mutate_its_input():
    body = {"apiResponse": read([issue(1, "CRITICAL"), issue(2, "LOW")])}
    snapshot = copy.deepcopy(body)
    load().transform(body)
    assert body == snapshot
