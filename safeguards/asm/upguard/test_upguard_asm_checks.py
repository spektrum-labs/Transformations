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
               {"domains": []}]

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

# What an empty list means differs by endpoint, per the vendor's public API spec: /domains documents a
# total_results count, so an empty domain list must state it as 0; /risks and /vulnerabilities document
# no count, so an empty list on the last page is the complete answer (a clean account).
EMPTY_MEASURED = {"nocriticalfindings": True, "nohighfindings": True, "isasmenabled": False,
                  "exploitedfindingscount": 0}


@pytest.mark.parametrize("extra", [
    {"total_results": 5},                                # the body says there is something, the list is empty
    {"total_results": False},                            # a bool is not a count
    {"total_results": "0"},                              # text is not a count
    {"total_results": 0, "next_page_token": "abc"},      # a count of 0 on a page that is not the last
    {"next_page_token": "abc"},                          # an empty page that is not the last
    {"error": True},                                     # an error marker beside the list
    {"errors": ["x"]},
])
def test_an_empty_list_that_is_not_a_complete_answer_is_not_evaluated(extra):
    for name, key in ALL_CHECKS:
        body = dict({LIST_OF[name]: []}, **extra)
        assert_not_evaluated(load(name)(body), key)


# Records that would each read as a verdict (a pass, a fail or a count) on a complete page. The same
# records on a page that is cut off, or beside an error marker, prove nothing about the account.
RECORDS_OF = {
    "nocriticalfindings": ([{"id": "r1", "severity": "low"}], [{"id": "r2", "severity": "critical"}]),
    "nohighfindings": ([{"id": "r1", "severity": "low"}], [{"id": "r2", "severity": "high"}]),
    "isasmenabled": ([{"hostname": "a.example", "active": True, "scanned_at": "2026-01-01T00:00:00Z"}],
                     [{"hostname": "b.example", "active": False}]),
    "exploitedfindingscount": ([{"id": "v1", "known_exploited_vulnerability": False}],
                               [{"id": "v2", "known_exploited_vulnerability": True}]),
}

PARTIAL = [
    {"next_page_token": "abc"},
    {"nextPageToken": "abc"},
    {"next_page": "abc"},
    {"next": "abc"},
    {"next_page_token": "abc", "total_results": 1},
    {"error": "boom"},
    {"error": True},
    {"errors": ["boom"]},
    {"errors": [{"message": "boom"}]},
]


@pytest.mark.parametrize("extra", PARTIAL)
def test_a_non_empty_page_that_is_cut_off_or_carries_an_error_is_not_evaluated(extra):
    for name, key in ALL_CHECKS:
        for records in RECORDS_OF[name]:
            body = dict({LIST_OF[name]: records}, **extra)
            assert_not_evaluated(load(name)(body), key)


@pytest.mark.parametrize("extra", PARTIAL)
def test_a_cut_off_page_or_error_on_a_response_wrapper_is_not_evaluated(extra):
    for name, key in ALL_CHECKS:
        for records in RECORDS_OF[name]:
            body = dict({"apiResponse": {LIST_OF[name]: records}}, **extra)
            assert_not_evaluated(load(name)(body), key)
            inner = {"apiResponse": dict({LIST_OF[name]: records}, **extra)}
            assert_not_evaluated(load(name)(inner), key)


@pytest.mark.parametrize("extra", [
    {},
    {"next_page_token": None, "total_results": 1},
    {"next_page_token": "", "errors": [], "error": None},
])
def test_a_complete_non_empty_page_still_reads_its_verdict(extra):
    expected = {"nocriticalfindings": (True, False), "nohighfindings": (True, False),
                "isasmenabled": (True, False), "exploitedfindingscount": (0, 1)}
    for name, key in ALL_CHECKS:
        for records, want in zip(RECORDS_OF[name], expected[name]):
            out = load(name)(dict({LIST_OF[name]: records}, **extra))
            assert out[key] == want
            assert "additionalInfo" not in out


def test_an_empty_domain_list_must_state_a_count_of_0():
    assert_not_evaluated(load("isasmenabled")({"domains": []}), "isASMEnabled")
    out = load("isasmenabled")({"domains": [], "total_results": 0, "next_page_token": None})
    assert out["isASMEnabled"] is False
    assert "additionalInfo" not in out


def test_an_empty_list_on_the_last_page_is_a_clean_account_where_the_vendor_documents_no_count():
    for name, key in ALL_CHECKS:
        if name == "isasmenabled":
            continue
        out = load(name)({LIST_OF[name]: [], "next_page_token": None})
        assert out[key] == EMPTY_MEASURED[name]
        assert "additionalInfo" not in out


def test_a_stated_zero_is_measured_for_every_check():
    for name, key in ALL_CHECKS:
        out = load(name)({LIST_OF[name]: [], "total_results": 0})
        assert out[key] == EMPTY_MEASURED[name]
        assert "additionalInfo" not in out


def test_the_stated_zero_is_read_through_a_response_wrapper():
    out = load("isasmenabled")({"apiResponse": {"domains": [], "total_results": 0}})
    assert out["isASMEnabled"] is False
    assert "additionalInfo" not in out


def test_the_text_never_echoes_the_body():
    for name, key in ALL_CHECKS:
        out = load(name)("VENDOR-DETAIL-0042 not json")
        assert "VENDOR-DETAIL-0042" not in repr(out)
        assert_not_evaluated(out, key)


class _UnreadableBody(dict):
    """A body whose every read raises with text that must never reach the result."""

    def _boom(self, *args, **kwargs):
        raise RuntimeError("VENDOR-DETAIL-0042")

    __contains__ = get = __getitem__ = keys = items = _boom


def test_an_unexpected_read_error_never_echoes_its_text():
    for name, key in ALL_CHECKS:
        out = load(name)(_UnreadableBody())
        assert "VENDOR-DETAIL-0042" not in repr(out)
        assert_not_evaluated(out, key)


def test_a_measured_answer_carries_no_data_collection_error():
    for name, body, key in (("nocriticalfindings", {"risks": []}, "noCriticalFindings"),
                            ("nohighfindings", {"risks": [{"severity": "critical"}]}, "noHighFindings"),
                            ("isasmenabled", {"domains": [], "total_results": 0}, "isASMEnabled")):
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
    assert load("nocriticalfindings")({"risks": []})["noCriticalFindings"] is True
    assert load("nocriticalfindings")({"risks": [{"severity": "severe"}]})["noCriticalFindings"] is False


def test_asm_enabled():
    t = load("isasmenabled")
    assert t({"domains": [{"hostname": "a.example", "active": True, "scanned_at": "2026-09-20T00:00:00Z"}]})["isASMEnabled"] is True
    assert t({"domains": [{"hostname": "a.example", "active": True}]})["isASMEnabled"] is False
    assert t({"domains": [], "total_results": 0})["isASMEnabled"] is False


def test_exploited_count():
    t = load("exploitedfindingscount")
    body = {"vulnerabilities": [{"hostname": "a", "known_exploited_vulnerability": True},
                                {"hostname": "b", "known_exploited_vulnerability": False}]}
    assert t(body)["exploitedFindingsCount"] == 1
    assert t({"vulnerabilities": []})["exploitedFindingsCount"] == 0
    assert t({"vulnerabilities": [{"hostname": "a"}]})["exploitedFindingsCount"] is None
