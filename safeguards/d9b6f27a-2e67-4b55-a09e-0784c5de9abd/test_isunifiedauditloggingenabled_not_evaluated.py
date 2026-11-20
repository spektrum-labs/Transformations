"""ENG-1291: an empty, error or refused audit-log read is Not evaluated, never False.

isunifiedauditloggingenabled.py reads Graph GET /beta/security/auditLog/queries, which lists
saved audit log SEARCHES, not audit records. It used to report False whenever that list was
empty (a tenant where nobody has run a search through the API) and on every error body, so a
tenant with Unified Audit Logging on was shown as failing. The criterion now comes back None
with dataCollection.status "error" (Not evaluated) in those cases, and True only from a
finished search that returned recent records. It never returns False.

The empty-list body below has the same shape as the one recorded for the reported tenant on
2026-11-16. All payloads are synthetic.
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).parent
KEY = "isUnifiedAuditLoggingEnabled"
ALIAS = "isUnifiedAuditLogEnabled"
SENTINEL = "DO-NOT-ECHO-VENDOR-TEXT"


def load():
    spec = importlib.util.spec_from_file_location("ual_eng1291", HERE / "isunifiedauditloggingenabled.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(body):
    return load().transform(body)


def day(offset_days):
    return (datetime.utcnow() + timedelta(days=offset_days)).strftime("%Y-%m-%dT00:00:00Z")


def query(status="succeeded", count=120, end_offset=-1, name="weekly review"):
    return {
        "@odata.type": "#microsoft.graph.security.auditLogQuery",
        "id": "00000000-0000-0000-0000-000000000001",
        "displayName": name,
        "filterStartDateTime": day(end_offset - 7),
        "filterEndDateTime": day(end_offset),
        "status": status,
        "approximateReturnedRecordCount": count,
    }


def listing(*queries):
    return {
        "@odata.context": "https://graph.microsoft.com/beta/$metadata#security/auditLog/queries",
        "@odata.count": len(queries),
        "value": list(queries),
    }


def assert_not_evaluated(out):
    assert out["transformedResponse"][KEY] is None
    assert out["transformedResponse"][ALIAS] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"], "a None verdict needs a reason on the channel the evaluator reads"
    assert out["additionalInfo"]["evaluation"]["failReasons"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


# --- the reported case ----------------------------------------------------------------------

def test_empty_search_list_is_not_evaluated_not_false():
    out = run(listing())
    assert_not_evaluated(out)
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert "can't tell" in reason
    assert out["additionalInfo"]["transformation"]["inputSummary"]["auditLogSearchesListed"] == 0


@pytest.mark.parametrize("wrap", [
    lambda b: b,
    lambda b: {"response": b},
    lambda b: {"apiResponse": b},
    lambda b: {"data": b, "validation": {"status": "passed", "errors": [], "warnings": []}},
    lambda b: json.dumps(b),
    lambda b: json.dumps(b).encode("utf-8"),
])
def test_empty_search_list_not_evaluated_in_every_input_shape(wrap):
    assert_not_evaluated(run(wrap(listing())))


# --- errors and refusals ----------------------------------------------------------------------

@pytest.mark.parametrize("code", ["Authorization_RequestDenied", "Forbidden", "InvalidAuthenticationToken"])
def test_permission_refusal_is_not_evaluated_and_names_the_permission(code):
    out = run({"error": {"code": code, "message": SENTINEL, "innerError": {"code": "x"}}})
    assert_not_evaluated(out)
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert "AuditLogsQuery.Read.All" in reason
    assert code in reason


def test_other_graph_error_is_not_evaluated():
    out = run({"error": {"code": "ServiceUnavailable", "message": SENTINEL}})
    assert_not_evaluated(out)
    assert "ServiceUnavailable" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("status", [401, 403, 500, "429"])
def test_http_status_error_body_is_not_evaluated(status):
    assert_not_evaluated(run({"statusCode": status, "body": SENTINEL}))


def test_vendor_error_text_is_not_echoed():
    out = run({"error": {"code": "Forbidden", "message": SENTINEL}})
    assert SENTINEL not in json.dumps(out)


@pytest.mark.parametrize("body", [
    {}, None, [], "", "null", {"value": None}, {"value": "x"}, {"unexpected": True},
])
def test_unreadable_or_unexpected_body_is_not_evaluated(body):
    assert_not_evaluated(run(body))


def test_failed_validation_is_not_evaluated():
    out = run({"data": listing(query()), "validation": {"status": "failed", "errors": ["bad"], "warnings": []}})
    assert_not_evaluated(out)


def test_malformed_json_is_not_evaluated():
    out = run("{not json")
    assert_not_evaluated(out)
    assert out["additionalInfo"]["transformation"]["status"] == "error"


# --- searches that prove nothing --------------------------------------------------------------

@pytest.mark.parametrize("q", [
    query(status="running"),
    query(status="failed"),
    query(status="notStarted"),
    query(count=0),
    query(count=None),
    query(end_offset=-200),
])
def test_searches_without_recent_records_are_not_evaluated(q):
    out = run(listing(q))
    assert_not_evaluated(out)
    assert out["additionalInfo"]["transformation"]["inputSummary"]["searchesWithRecentRecords"] == 0


def test_never_returns_false_for_any_probe():
    bodies = [listing(), listing(query(count=0)), {"error": {"code": "Forbidden"}}, {}, None,
              {"value": []}, {"enabled": False}, {"auditEnabled": False}]
    for body in bodies:
        assert run(body)["transformedResponse"][KEY] is not False


# --- real evidence ------------------------------------------------------------------------------

def test_succeeded_search_with_recent_records_is_true():
    out = run(listing(query(count=4521, end_offset=-2)))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"][ALIAS] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []
    assert out["additionalInfo"]["evaluation"]["additionalFindings"][0]["approximateReturnedRecordCount"] == 4521


def test_true_when_any_one_search_qualifies():
    out = run(listing(query(status="failed"), query(count=0), query(count=12, name="ok")))
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["searchesWithRecentRecords"] == 1


def test_record_count_as_string_is_accepted():
    assert run(listing(query(count="37")))["transformedResponse"][KEY] is True
