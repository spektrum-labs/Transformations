"""SecurityScorecard (Cyber Risk Quantification): fail-closed checks over getCompanyDetails.

Bodies are SYNTHETIC: the vendor's public API reference (securityscorecard.readme.io, "Get a company
information and scorecard summary") names the fields of CompanySummary (name, domain, grade A to F or "?",
score 0 to 100, undefined while calculating) but not what an error or refused body looks like, so the error
shapes here are the ones Integration-Service hands over (a statusCode or error flag, optionally wrapped, as a
dict or a JSON string). Domains are the reserved example.com. No customer data.

Rules under test: an error, 401/403, empty, unrecognised, incomplete or still-calculating body is Not
evaluated: the value is null and additionalInfo.dataCollection.status is "error". Never 0, never False.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "securityRatingScore"


def load():
    spec = importlib.util.spec_from_file_location("securityscorecard_" + KEY, HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(body):
    return load().transform(copy.deepcopy(body))


def value(body):
    return result(body)["transformedResponse"][KEY]


def card(**over):
    row = {"name": "Example Ltd.", "domain": "example.com", "grade": "B", "score": 84,
           "industry": "technology", "grade_url": "https://example.com/grade.png"}
    row.update(over)
    return row


def not_evaluated(body):
    out = result(body)
    assert out["transformedResponse"] == {KEY: None}
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]
    return out


@pytest.mark.parametrize("grade,score", [("A", 97), ("B", 84), ("C", 71), ("D", 62), ("F", 12), ("A", 100), ("F", 0)])
def test_the_vendor_score_is_returned_as_given(grade, score):
    out = result(card(grade=grade, score=score))
    assert out["transformedResponse"] == {KEY: score}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


def test_a_low_score_is_still_a_measurement_not_an_error():
    out = result(card(grade="F", score=3))
    assert out["transformedResponse"][KEY] == 3
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_the_finding_names_the_domain_the_score_and_the_grade():
    domain = "example.org"
    out = result(card(domain=domain, grade="C", score=75))
    finding = out["additionalInfo"]["evaluation"]["additionalFindings"][0]
    assert finding == f"SecurityScorecard rates {domain} 75 out of 100 (grade C)"


def test_only_the_key_is_returned_so_no_second_criterion_leaks():
    assert list(result(card())["transformedResponse"]) == [KEY]


@pytest.mark.parametrize("wrap", [
    lambda b: b,
    lambda b: {"apiResponse": b},
    lambda b: {"status": 200, "apiResponse": b},
    lambda b: {"apiResponse": {"data": b}},
    lambda b: {"apiResponse": json.dumps(b)},
    lambda b: {"response": {"result": b}},
    lambda b: json.dumps(b),
    lambda b: json.dumps({"apiResponse": b}),
])
def test_the_body_is_found_under_any_wrapper(wrap):
    assert value(wrap(card(score=77, grade="C"))) == 77


@pytest.mark.parametrize("body", [
    {},
    None,
    "",
    "{}",
    "[]",
    "not json at all",
    [],
    [card()],
    {"apiResponse": {}},
    {"apiResponse": "{}"},
    {"apiResponse": None},
    {"unrelated": [1, 2, 3], "items": []},
    {"message": "Something went wrong"},
    {"detail": "Forbidden"},
    {"apiResponse": {"message": "Forbidden"}},
    {"entries": [{"issue": "x", "count": 2}], "total": 1},
])
def test_an_empty_or_unrecognised_body_is_not_evaluated(body):
    not_evaluated(body)


@pytest.mark.parametrize("body", [
    {"error": True, "statusCode": 401, "message": "Unauthorized"},
    {"error": True, "statusCode": 403, "message": "Forbidden"},
    {"error": {"message": "Invalid token"}},
    {"error": "Not Found"},
    {"statusCode": 403, "message": "Forbidden"},
    {"statusCode": 404, "message": "Not Found"},
    {"statusCode": 429, "message": "Too Many Requests"},
    {"statusCode": 500, "message": "Internal Server Error"},
    {"errorType": "AuthError", "message": "bad token"},
    {"status": 401, "apiResponse": {"message": "Unauthorized"}},
    {"status": False, "message": "refused"},
    {"apiResponse": {"statusCode": 403, "message": "Forbidden"}},
    {"apiResponse": {"error": {"message": "Invalid token"}}},
    {"apiResponse": json.dumps({"error": True, "statusCode": 401, "message": "Unauthorized"})},
])
def test_an_error_or_refused_answer_is_not_evaluated(body):
    not_evaluated(body)


def test_an_error_next_to_a_scorecard_is_still_an_error():
    body = card()
    body.update({"statusCode": 403, "message": "Forbidden"})
    not_evaluated(body)


@pytest.mark.parametrize("bad_grade", ["?", "", "E", "a", "A+", None, 4, True, [], {}])
def test_a_grade_that_is_not_a_to_f_is_not_evaluated(bad_grade):
    not_evaluated(card(grade=bad_grade))


def test_a_scorecard_with_no_grade_field_is_not_evaluated():
    body = card()
    del body["grade"]
    not_evaluated(body)


def test_a_scorecard_still_calculating_has_no_score_and_is_not_evaluated():
    body = card(grade="?")
    del body["score"]
    not_evaluated(body)


def test_a_missing_score_is_not_evaluated():
    body = card()
    del body["score"]
    not_evaluated(body)


@pytest.mark.parametrize("bad_score", ["84", None, True, False, 84.5, -1, 101, 1000, [], {}])
def test_a_score_that_is_not_a_whole_number_from_0_to_100_is_not_evaluated(bad_score):
    not_evaluated(card(score=bad_score))


@pytest.mark.parametrize("bad_domain", [None, "", "   ", 5, [], {}])
def test_a_scorecard_without_a_company_domain_is_not_evaluated(bad_domain):
    not_evaluated(card(domain=bad_domain))


def test_a_scorecard_with_no_domain_field_is_not_evaluated():
    body = card()
    del body["domain"]
    not_evaluated(body)


@pytest.mark.parametrize("body", [{"score": 90}, {"grade": "A"}, {"score": 90, "name": "x"}, {"apiResponse": {"score": 55}}])
def test_a_body_that_only_happens_to_hold_a_score_field_is_not_a_scorecard(body):
    not_evaluated(body)


def test_a_value_is_never_false_or_a_bare_zero_when_nothing_was_measured():
    for body in ({}, None, "", {"statusCode": 403}, card(grade="?")):
        assert result(body)["transformedResponse"][KEY] is None


def test_the_transform_does_not_mutate_its_input():
    body = {"apiResponse": card(score=66, grade="D")}
    snapshot = copy.deepcopy(body)
    load().transform(body)
    assert body == snapshot
