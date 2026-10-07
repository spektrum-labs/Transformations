"""epp_transform fail-closed back-port (7 Oct 2026) and the three keys that were aliases of isEPPDeployed.

isEDRDeployed, isEPPLoggingEnabled and isEPPEnabledForCriticalSystems all read "Endpoint Protection > 0",
and the critical-systems count was computers-only, so no server could move it. An empty or unreadable read
came back as measured False with dataCollection "success". Synthetic bodies only, in the shape of the
Sophos Endpoint API v1 GET /endpoints reference (field names and enum values verbatim from it).
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
SEEN = "2026-10-01T00:00:00.000Z"


def load():
    spec = importlib.util.spec_from_file_location("sophos_epp_fail_closed", HERE / "epp_transform.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EPP = load()


def endpoint(kind, products, installed=True, **extra):
    record = {"id": "e-" + kind, "type": kind, "hostname": "synthetic-" + kind, "lastSeenAt": SEEN,
              "health": {"overall": "good", "services": {"status": "good", "serviceDetails": []}},
              "assignedProducts": [{"code": c, "version": "1", "status": "installed" if installed else "notInstalled"}
                                   for c in products]}
    record.update(extra)
    return record


def run(body):
    out = EPP.transform(body)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]["status"]


FULL = ["coreAgent", "endpointProtection", "interceptX", "xdr"]
PASS_BODY = {"items": [endpoint("computer", FULL), endpoint("server", FULL)],
             "pages": {"size": 2, "maxSize": 500}}


def test_pass_body_measures_each_key_on_its_own():
    tr, status = run(PASS_BODY)
    assert status == "success"
    assert tr["isEPPDeployed"] is True
    assert tr["isEDRDeployed"] is True
    assert tr["edrDeployedPercentage"] == 100.0
    assert tr["isEPPEnabledForCriticalSystems"] is True
    assert tr["isEPPLoggingEnabled"] is None


def test_edr_is_not_an_alias_of_epp():
    body = {"items": [endpoint("computer", ["coreAgent", "endpointProtection", "interceptX"]),
                      endpoint("server", ["coreAgent", "endpointProtection"])]}
    tr, status = run(body)
    assert status == "success"
    assert tr["isEPPDeployed"] is True
    assert tr["isEDRDeployed"] is False
    assert tr["edrDeployedPercentage"] == 0.0


def test_edr_below_threshold_fails():
    items = [endpoint("computer", FULL) for _ in range(9)] + [endpoint("computer", ["endpointProtection"])]
    tr, _ = run({"items": items})
    assert tr["edrDeployedPercentage"] == 90.0
    assert tr["isEDRDeployed"] is False


def test_critical_systems_reads_servers():
    body = {"items": [endpoint("computer", FULL), endpoint("server", ["coreAgent", "xdr"])]}
    tr, status = run(body)
    assert status == "success"
    assert tr["isEPPDeployed"] is True
    assert tr["isEPPEnabledForCriticalSystems"] is False


def test_critical_systems_without_servers_is_not_answered():
    tr, status = run({"items": [endpoint("computer", FULL)]})
    assert status == "success"
    assert tr["isEPPEnabledForCriticalSystems"] is None


def test_not_installed_product_protects_nothing():
    tr, _ = run({"items": [endpoint("computer", FULL, installed=False), endpoint("server", FULL, installed=False)]})
    assert tr["isEPPDeployed"] is False
    assert tr["isEDRDeployed"] is False
    assert tr["isEPPEnabledForCriticalSystems"] is False


@pytest.mark.parametrize("value,expected", [(None, 0), ("unknown", 0), ("", 0), (False, 0), ("false", 0),
                                            (True, 100), ("true", 100)])
def test_mdr_managed_counts_only_when_explicitly_true(value, expected):
    tr, _ = run({"items": [endpoint("computer", ["endpointProtection"], mdrManaged=value)]})
    assert tr["MDR"] == expected


def test_body_cannot_answer_its_own_configured_key():
    body = {"isEPPConfigured": True, "items": [endpoint("computer", ["coreAgent"])]}
    tr, _ = run(body)
    assert tr["isEPPConfigured"] is False


NO_EVIDENCE = [
    None, {}, [], "", "{}", {"items": []}, {"items": None}, {"items": "x"},
    {"items": ["not-an-endpoint"]}, {"items": [{"unrelated": 1}]},
    {"error": "forbidden", "message": "Access denied", "code": "OAuth:AccessDenied"},
    {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 502,
     "message": "Pagination stopped at page 2"},
    {"statusCode": 429, "items": [endpoint("computer", FULL)]},
    {"items": [endpoint("computer", FULL)], "pages": {"nextKey": "abc", "size": 1, "maxSize": 500}},
    {"items": [endpoint("computer", FULL)], "pages": {"nextKey": None, "truncated": True, "scannedCount": 1}},
    {"data": [], "validation": {"status": "unknown", "errors": [], "warnings": []}},
    {"data": PASS_BODY, "validation": {"status": "failed", "errors": ["x"], "warnings": []}},
]


@pytest.mark.parametrize("body", NO_EVIDENCE, ids=lambda b: json.dumps(b)[:50])
def test_no_evidence_is_unevaluated_for_every_key(body):
    tr, status = run(body)
    assert status == "error"
    assert all(value is None for value in tr.values())


class Poisoned(dict):
    """A dict whose every read raises: drives the except branch."""

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned")

    def __getitem__(self, key):
        raise RuntimeError("poisoned")

    def __contains__(self, key):
        raise RuntimeError("poisoned")


def test_poisoned_body_is_unevaluated():
    tr, status = run(Poisoned(items=[1]))
    assert status == "error"
    assert all(value is None for value in tr.values())


def test_unread_page_markers_that_mean_end_of_list_are_not_truncation():
    for pages in ({"nextKey": None}, {"nextKey": "None"}, {"nextKey": ""}, {"size": 1, "maxSize": 500}):
        tr, status = run({"items": [endpoint("computer", FULL)], "pages": pages})
        assert status == "success"
        assert tr["isEPPDeployed"] is True
