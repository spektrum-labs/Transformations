"""UpGuard (Attack Surface Management) checks on bodies shaped like the public API spec
(cyber-risk.upguard.com/api/swagger.json). No customer body has been seen."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("ug_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"hello": "world"},
               "not json", {"error": True, "message": "HTTP 503"}, {"data": None},
               {"risks": [], "domains": [], "vulnerabilities": []}]

ALL_CHECKS = [("nocriticalfindings", "noCriticalFindings"), ("nohighfindings", "noHighFindings"),
              ("isasmenabled", "isASMEnabled"), ("exploitedfindingscount", "exploitedFindingsCount")]


def assert_not_evaluated(out, key):
    """None for the criterion, and a data collection error so the evaluator shows Not evaluated."""
    assert out[key] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


@pytest.mark.parametrize("body", FAIL_CLOSED)
def test_a_body_that_proves_nothing_is_not_evaluated(body):
    for name, key in ALL_CHECKS:
        assert_not_evaluated(load(name)(body), key)


@pytest.mark.parametrize("name,key,body", [
    ("nocriticalfindings", "noCriticalFindings", {"risks": "oops"}),
    ("nocriticalfindings", "noCriticalFindings", {"risks": None}),
    ("nocriticalfindings", "noCriticalFindings", {"risks": ["x", 1, None]}),
    ("nohighfindings", "noHighFindings", {"risks": "oops"}),
    ("nohighfindings", "noHighFindings", {"risks": None}),
    ("nohighfindings", "noHighFindings", {"risks": ["x", 1, None]}),
    ("isasmenabled", "isASMEnabled", {"domains": "oops"}),
    ("isasmenabled", "isASMEnabled", {"domains": None}),
    ("isasmenabled", "isASMEnabled", {"domains": ["x", 1, None]}),
])
def test_a_list_that_is_not_a_list_of_records_is_not_evaluated(name, key, body):
    assert_not_evaluated(load(name)(body), key)


LIST_OF = {"nocriticalfindings": "risks", "nohighfindings": "risks", "isasmenabled": "domains",
           "exploitedfindingscount": "vulnerabilities"}


@pytest.mark.parametrize("extra", [
    {},                                          # an empty list that states nothing is not a read
    {"total": 5},                                # the body says there is something, the list is empty
    {"total": False},                            # a bool is not a count
    {"total": "0"},                              # text is not a count
    {"total": 0, "next_page_token": "abc"},      # a count of 0 on a page that is not the last
])
def test_an_empty_list_without_a_stated_zero_is_not_evaluated(extra):
    for name, key in ALL_CHECKS:
        body = dict({LIST_OF[name]: []}, **extra)
        assert_not_evaluated(load(name)(body), key)


@pytest.mark.parametrize("count_key", ["total", "count", "total_count", "totalCount", "total_results", "totalResults"])
def test_an_empty_list_with_a_stated_zero_is_measured(count_key):
    expected = {"nocriticalfindings": True, "nohighfindings": True, "isasmenabled": False,
                "exploitedfindingscount": 0}
    for name, key in ALL_CHECKS:
        out = load(name)({LIST_OF[name]: [], count_key: 0})
        assert out[key] == expected[name]
        assert "additionalInfo" not in out


def test_the_stated_zero_is_read_through_a_response_wrapper():
    out = load("nocriticalfindings")({"apiResponse": {"risks": [], "total": 0}})
    assert out["noCriticalFindings"] is True


def test_the_text_never_echoes_the_body():
    for name, key in ALL_CHECKS:
        out = load(name)("VENDOR-DETAIL-0042 not json")
        assert "VENDOR-DETAIL-0042" not in repr(out)
        assert_not_evaluated(out, key)


def test_a_measured_answer_carries_no_data_collection_error():
    for name, body, key in (("nocriticalfindings", {"risks": [], "total": 0}, "noCriticalFindings"),
                            ("nohighfindings", {"risks": [{"severity": "critical"}]}, "noHighFindings"),
                            ("isasmenabled", {"domains": [], "total": 0}, "isASMEnabled")):
        out = load(name)(body)
        assert out[key] is not None
        assert "additionalInfo" not in out


def test_severity_checks():
    high_only = {"risks": [{"id": "r1", "severity": "high"}]}
    assert load("nocriticalfindings")(high_only)["noCriticalFindings"] is True
    assert load("nohighfindings")(high_only)["noHighFindings"] is False
    crit = {"apiResponse": {"risks": [{"id": "r2", "severity": "critical"}]}}
    assert load("nocriticalfindings")(crit)["noCriticalFindings"] is False
    assert load("nohighfindings")(crit)["noHighFindings"] is True
    assert load("nocriticalfindings")({"risks": [], "total": 0})["noCriticalFindings"] is True
    assert load("nocriticalfindings")({"risks": [{"severity": "severe"}]})["noCriticalFindings"] is False


def test_asm_enabled():
    t = load("isasmenabled")
    assert t({"domains": [{"hostname": "a.example", "active": True, "scanned_at": "2026-09-20T00:00:00Z"}]})["isASMEnabled"] is True
    assert t({"domains": [{"hostname": "a.example", "active": True}]})["isASMEnabled"] is False
    assert t({"domains": [], "total": 0})["isASMEnabled"] is False


def test_exploited_count():
    t = load("exploitedfindingscount")
    body = {"vulnerabilities": [{"hostname": "a", "known_exploited_vulnerability": True},
                                {"hostname": "b", "known_exploited_vulnerability": False}]}
    assert t(body)["exploitedFindingsCount"] == 1
    assert t({"vulnerabilities": [], "total": 0})["exploitedFindingsCount"] == 0
    assert t({"vulnerabilities": [{"hostname": "a"}]})["exploitedFindingsCount"] is None
