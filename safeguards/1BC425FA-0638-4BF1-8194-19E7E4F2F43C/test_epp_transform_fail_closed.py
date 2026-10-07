"""epp_transform fail-closed back-port (7 Oct 2026) and the three keys that were aliases of isEPPDeployed.

isEDRDeployed, isEPPLoggingEnabled and isEPPEnabledForCriticalSystems all read "Endpoint Protection > 0",
and the critical-systems count was computers-only, so no server could move it. An empty or unreadable read
came back as measured False with dataCollection "success". Synthetic bodies only, in the shape of the
Sophos Endpoint API v1 GET /endpoints reference (field names and enum values verbatim from it).

Extended after the 2026-10-07 review of PR #1067: a servers-only estate, a dark fleet, a list with no
computer or server in it, the envelope truncation marker that is the only one a bare-list delivery
carries, and xdr no longer counting as a managed service.
"""
import importlib.util
import json
import pathlib
from datetime import datetime

import pytest

HERE = pathlib.Path(__file__).parent
# Relative to now: active_endpoints treats a fleet whose newest check-in is over 15 days old as dark.
SEEN = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")


def load():
    spec = importlib.util.spec_from_file_location("sophos_epp_fail_closed", HERE / "epp_transform.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EPP = load()


def endpoint(kind, products, installed=True, seen=SEEN, **extra):
    record = {"id": "e-" + kind, "type": kind, "hostname": "synthetic-" + kind, "lastSeenAt": seen,
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
    # Not answered from this method, so not emitted at all: see test_logging_key_is_not_emitted.
    assert "isEPPLoggingEnabled" not in tr


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
    """KNOWN GAP, pinned deliberately rather than silently.

    None beside dataCollection "success" does NOT reach the evaluator as "not evaluated".
    Token-Service has one not-evaluated channel and it covers the whole response
    (evaluate.py _data_collection_failure_message); within a successful read,
    extract_measured_value returns the whole response both for a key whose value is None and for a
    key that is absent, so compare_values grades either as a measured failure. Omitting the key
    therefore changes nothing -- verified against that function. A workstation-only MDR tenant is
    red on this criterion until Token-Service grows a per-key channel or the RTA row is scoped to
    tenants that have servers. The alternative, a vacuous True on an estate with no server in the
    list, would be a measured pass nobody measured, which is worse.
    """
    tr, status = run({"items": [endpoint("computer", FULL)]})
    assert status == "success"
    assert tr["isEPPEnabledForCriticalSystems"] is None


def test_logging_key_is_not_emitted():
    """GET /endpoints reports no logging or telemetry setting, so the file does not answer the key."""
    tr, status = run(PASS_BODY)
    assert status == "success"
    assert "isEPPLoggingEnabled" not in tr
    findings = EPP.transform(PASS_BODY)["additionalInfo"]["evaluation"]["additionalFindings"]
    assert any("isEPPLoggingEnabled" in str(finding) for finding in findings)


def test_servers_only_estate_is_measured_not_graded_red():
    """An estate of protected servers is protected. "Endpoint Protection" counts computers only and
    percentage(0, 0) is 0, so this read used to come back isEPPEnabled False, isEPPConfigured False,
    isEPPMisconfigured True and requiredCoveragePercentage 0 -- measured red for a fully covered estate."""
    tr, status = run({"items": [endpoint("server", FULL), endpoint("server", FULL)]})
    assert status == "success"
    assert tr["isEPPEnabled"] is True
    assert tr["isEPPDeployed"] is True
    assert tr["isEndpointSecurityEnabled"] is True
    assert tr["isEPPConfigured"] is True
    assert tr["isEPPMisconfigured"] is False
    assert tr["requiredCoveragePercentage"] == 100
    assert tr["requiredConfigurationPercentage"] == 100
    assert tr["isEPPEnabledForCriticalSystems"] is True


def test_half_covered_mixed_estate_counts_computers_and_servers():
    body = {"items": [endpoint("computer", FULL), endpoint("server", ["coreAgent"])]}
    tr, status = run(body)
    assert status == "success"
    assert tr["requiredCoveragePercentage"] == 50
    assert tr["isEPPEnabled"] is True
    assert tr["isEPPEnabledForCriticalSystems"] is False


def test_dark_fleet_is_unevaluated():
    """Newest check-in older than the active window: every endpoint is stale, so every denominator is
    zero and every coverage read 0% with dataCollection "success"."""
    old = "2026-01-01T00:00:00.000Z"
    tr, status = run({"items": [endpoint("computer", FULL, seen=old), endpoint("server", FULL, seen=old)]})
    assert status == "error"
    # The stale count is the reason the read proves nothing, so it is reported (endpoint rules,
    # 2026-09-29). Every verdict is still not evaluated, because dataCollection is an error.
    assert tr["staleEndpointCount"] == 2
    assert all(value is None for key, value in tr.items() if key != "staleEndpointCount")


def test_estate_with_no_computer_or_server_is_unevaluated():
    tr, status = run({"items": [endpoint("mobile", ["mobileProtection"])]})
    assert status == "error"
    assert all(value is None for key, value in tr.items() if key != "staleEndpointCount")


def test_envelope_truncation_marker_is_seen_on_a_bare_list():
    """A bare-array delivery has no body for Integration-Service to write pages.truncated into, so the
    envelope flag paginationTruncated is the only marker it carries."""
    body = {"data": [endpoint("computer", FULL)],
            "validation": {"status": "success", "errors": [], "warnings": []},
            "paginationTruncated": True}
    tr, status = run(body)
    assert status == "error"
    assert all(value is None for value in tr.values())


def test_envelope_truncation_marker_is_seen_on_a_dict_body():
    for body in ({"items": [endpoint("computer", FULL)], "paginationTruncated": True},
                 {"items": [endpoint("computer", FULL)], "pages": {"paginationTruncated": "true"}},
                 {"api_response": {"items": [endpoint("computer", FULL)], "paginationTruncated": True}}):
        tr, status = run(body)
        assert status == "error"
        assert all(value is None for value in tr.values())


def test_partly_unreadable_list_is_unevaluated():
    """One unreadable item used to be dropped silently and the remainder scored as the whole estate."""
    for junk in ({"garbage": 1}, "not-an-endpoint", 7, None):
        tr, status = run({"items": [endpoint("computer", FULL), junk]})
        assert status == "error"
        assert all(value is None for key, value in tr.items() if key != "staleEndpointCount")


def test_xdr_alone_is_not_managed_detection_and_response():
    """xdr is Intercept X Advanced with XDR, which the customer runs; mtr is the managed service."""
    tr, status = run({"items": [endpoint("computer", ["coreAgent", "endpointProtection", "xdr"])]})
    assert status == "success"
    assert tr["MDR"] == 0
    assert tr["isMDREnabled"] is False
    assert tr["isEDRDeployed"] is True
    tr, _ = run({"items": [endpoint("computer", ["coreAgent", "endpointProtection", "mtr"])]})
    assert tr["MDR"] == 100
    assert tr["isMDREnabled"] is True


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
