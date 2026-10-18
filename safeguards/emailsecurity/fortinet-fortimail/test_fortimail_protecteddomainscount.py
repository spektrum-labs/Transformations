"""FortiMail protectedDomainsCount: GET /api/v1/Domain/ -> number of protected domains.

Fixture shape: the "Get Configured Domains" output Fortinet documents for its FortiSOAR connector
(top level objectID, reqAction, totalRemoteCount, subCount, nextPage, collection[...]); every value is
invented. Real-shaped, flipped, empty, None and error input.
"""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fortimail_protecteddomainscount", HERE / "protecteddomainscount.py")
MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOD)

REAL = json.loads((HERE / "fixtures" / "domain_list_documented_shape.json").read_text())


def run(body):
    out = MOD.transform(body)
    return out["transformedResponse"][MOD.KEY], out["additionalInfo"]["dataCollection"]["status"]


def test_real_shape_counts_domains_and_leaves_out_the_association():
    assert run(REAL) == (2, "success")
    out = MOD.transform(REAL)
    assert out["transformedResponse"]["domainAssociationCount"] == 1
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


def test_same_body_in_every_wrapper_the_pipeline_uses():
    assert run(json.dumps(REAL)) == (2, "success")
    assert run({"apiResponse": REAL}) == (2, "success")
    assert run({"response": {"result": {"apiResponse": REAL}}}) == (2, "success")
    assert run({"data": REAL, "validation": {"status": "passed", "errors": [], "warnings": []}}) == (2, "success")
    assert run(json.dumps(REAL).encode()) == (2, "success")


def test_flipped_no_domain_left_is_a_measured_zero():
    flipped = copy.deepcopy(REAL)
    flipped["collection"] = []
    assert run(flipped) == (0, "success")
    only_alias = copy.deepcopy(REAL)
    only_alias["collection"] = [REAL["collection"][2]]
    assert run(only_alias) == (0, "success")
    assert MOD.transform(flipped)["additionalInfo"]["evaluation"]["failReasons"]


def test_association_flag_encodings():
    for flag, expected in [(True, 1), ("1", 1), ("true", 1), (1, 1), (False, 2), ("0", 2), ("false", 2), (0, 2), (None, 2), ("", 2)]:
        body = copy.deepcopy(REAL)
        body["collection"] = [
            {"mkey": "one.example.test", "is_association": False},
            {"mkey": "two.example.test", "is_association": flag},
        ]
        assert run(body)[0] == expected, flag


def test_entries_without_a_name_are_not_domains():
    body = {"collection": [{"mkey": ""}, {"maindomain": "x"}, "text", None, {"mkey": "ok.example.test"}]}
    assert run(body) == (1, "success")


def test_error_bodies_are_not_measured():
    for body in (
        {"error": True, "message": "HTTP 403 Forbidden"},
        {"statusCode": 403, "error": "Forbidden"},
        {"status_code": 401, "error": "Unauthorized"},
        {"error": {"type": "authentication_error", "message": "invalid credentials"}},
        {"apiResponse": {"error": True, "message": "login failed"}},
        {"errorType": "outbound_blocked", "statusCode": 400},
    ):
        assert run(body) == (None, "error"), body


def test_empty_and_unrelated_bodies_are_not_measured():
    for body in ({}, "{}", [], None, "", "not json", {"hello": "world"}, {"collection": "none"}, {"collection": {}}, b"\xff"):
        assert run(body) == (None, "error"), body
