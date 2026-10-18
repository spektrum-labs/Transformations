"""hasActiveIncidentTicketing: True only from a PSA ticket id on an incident report; None when nothing can prove it."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "hasActiveIncidentTicketing"


def load():
    spec = importlib.util.spec_from_file_location("huntress_ticketing", os.path.join(HERE, KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def report(i, tickets=None, status="closed"):
    return {"id": i, "status": status, "severity": "high", "psa_ticket_eids": tickets if tickets is not None else []}


def body(items, next_token=None, truncated=False):
    pagination = {"next_page_token": next_token, "next_page_url": None}
    if truncated:
        pagination["truncated"] = True
    return {"data": {"apiResponse": {"incident_reports": items, "pagination": pagination}},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}


def run(payload):
    return load()(payload)


def value(payload):
    return run(payload)["transformedResponse"][KEY]


def not_evaluated(out):
    return out["transformedResponse"][KEY] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_a_ticket_on_any_report_is_routing():
    out = run(body([report(1), report(2, ["T-1001"]), report(3)]))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["ticketedIncidentReports"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_numeric_ticket_ids_count():
    assert value(body([report(1, [4821])])) is True


def test_a_complete_read_with_no_ticket_is_false():
    out = run(body([report(1), report(2, []), report(3, [None, "", "  "])]))
    assert out["transformedResponse"][KEY] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]


def test_flipping_the_ticket_flips_the_answer():
    assert value(body([report(1, ["T-1"])])) is True
    assert value(body([report(1, [])])) is False


def test_a_missing_or_malformed_ticket_field_is_no_ticket():
    reports = [{"id": 1}, {"id": 2, "psa_ticket_eids": None}, {"id": 3, "psa_ticket_eids": "T-1"}, {"id": 4, "psa_ticket_eids": [True]}]
    assert value(body(reports)) is False


def test_no_incidents_proves_nothing():
    assert not_evaluated(run(body([])))


@pytest.mark.parametrize("flag", ["next", "truncated"])
def test_partial_read_without_a_ticket_is_not_measured(flag):
    payload = body([report(1)], next_token="abc") if flag == "next" else body([report(1)], truncated=True)
    assert not_evaluated(run(payload))


@pytest.mark.parametrize("flag", ["next", "truncated"])
def test_partial_read_with_a_ticket_still_proves_routing(flag):
    items = [report(1), report(2, ["T-9"])]
    payload = body(items, next_token="abc") if flag == "next" else body(items, truncated=True)
    assert value(payload) is True


def test_a_list_with_no_pagination_block_cannot_show_a_negative():
    payload = {"data": {"apiResponse": {"incident_reports": [report(1)]}}, "validation": {}}
    assert not_evaluated(run(payload))
    payload = {"data": {"apiResponse": {"incident_reports": [report(1, ["T-1"])]}}, "validation": {}}
    assert value(payload) is True


def test_entries_that_are_not_records_are_not_scored():
    assert not_evaluated(run(body(["a", "b"])))
    assert not_evaluated(run(body([report(1), "x"])))


NO_EVIDENCE = [
    None, {}, [], "", "{}",
    {"errors": ["Unauthorized"]},
    {"error": "invalid credentials", "status_code": 401},
    {"status": 403, "message": "Forbidden"},
    {"data": {"apiResponse": {"errors": ["Unauthorized"]}}, "validation": {}},
    {"data": {"apiResponse": {"status": 500, "message": "boom"}}, "validation": {}},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
]


@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(payload):
    assert not_evaluated(run(payload))
