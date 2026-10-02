"""ManageEngine Endpoint Central: isEDRDeployed / isEPPDeployed (SoM summary) and isPatchManagementValid (patch
summary + health policy workflow).

Synthetic bodies in ManageEngine's documented shapes only (API reference samples for GET /api/1.4/som/summary,
GET /api/1.4/patch/summary and GET /api/1.4/patch/healthpolicy); no customer data. Each check answers only from a
complete read and is not evaluated (value None, dataCollection "error") on a missing, empty or failed one.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("me_som_patch_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


EDR = load("isedrdeployed")
EPP = load("iseppdeployed")
PATCH = load("ispatchmanagementvalid")
SOM_CHECKS = [(EDR, "isEDRDeployed"), (EPP, "isEPPDeployed")]


def run(fn, body, key):
    out = fn(copy.deepcopy(body))
    return out["transformedResponse"].get(key), out["additionalInfo"]["dataCollection"]["status"], out


# ------------------------------------------------------------------ SoM summary bodies

def som_cloud(installed, total, as_str=True, live=None, down=None, over30=3):
    conv = str if as_str else int
    summary = {
        "installation_status_summary": {"uninstallation_failed": conv(0), "installed": conv(installed),
                                        "total": conv(total), "installation_failed": conv(1),
                                        "yet_to_install": conv(max(total - installed - 1, 0)), "uninstalled": conv(0)},
        "last_contact_time_summary": {"equal_3_day": conv(1), "4_day_to_7_day": conv(0), "8_day_to_15_day": conv(0),
                                      "16_day_to_30_day": conv(0), "greater_30_day": conv(over30)},
    }
    if live is not None:
        summary["live_status_summary"] = {"live": conv(live), "down": conv(down), "unknown": conv(0)}
    return {"message_type": "summary", "message_response": {"summary": summary}, "message_version": "1.4",
            "status": "success"}


def som_onprem(installed, total):
    """The on-premises API reference sample: same nesting, numeric counts, no live_status_summary."""
    return som_cloud(installed, total, as_str=False)


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_cloud_nested_string_counts_are_read(fn, key):
    value, status, out = run(fn, som_cloud(95, 100, live=60, down=35), key)
    assert (value, status) == (True, "success")
    result = out["transformedResponse"]
    assert result["totalEndpoints"] == 100
    assert result["coveragePercentage"] == 95.0
    assert result["downAgentCount"] == 35
    assert any("down" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_onprem_numeric_counts_are_read(fn, key):
    assert run(fn, som_onprem(9, 10), key)[:2] == (True, "success")


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_low_coverage_is_a_real_false(fn, key):
    value, status, out = run(fn, som_cloud(50, 100), key)
    assert (value, status) == (False, "success")
    assert "below" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_threshold_is_inclusive_at_80(fn, key):
    assert run(fn, som_cloud(80, 100), key)[0] is True
    assert run(fn, som_cloud(79, 100), key)[0] is False


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_message_response_already_stripped(fn, key):
    body = som_cloud(90, 100)["message_response"]
    assert run(fn, body, key)[:2] == (True, "success")
    assert run(fn, body["summary"], key)[:2] == (True, "success")


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_wrapped_in_api_response_and_json_string(fn, key):
    assert run(fn, {"apiResponse": som_cloud(90, 100)}, key)[:2] == (True, "success")
    assert run(fn, json.dumps(som_cloud(90, 100)), key)[:2] == (True, "success")


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_flat_count_keys_still_accepted(fn, key):
    assert run(fn, {"total_computers": 10, "managed_computers": 9}, key)[:2] == (True, "success")
    assert run(fn, {"total_computers": 10, "agent_installed_count": 2}, key)[:2] == (False, "success")


NO_EVIDENCE = [
    None, {}, [], "", "null", 0,
    {"status": "error", "error_code": "1010", "error_description": "User is not authorized to access this API",
     "message_type": "som", "message_version": "1.4"},
    {"status": "error", "message": "Integrator SRN not available"},
    {"message": "Integrator SRN not available", "status": "Not Available"},
    {"error": True, "message": "401 Unauthorized"},
    {"errorCode": "10002", "errorMessage": "Invalid OAuth token"},
    {"message_type": "summary", "status": "success", "message_version": "1.4", "message_response": {}},
    {"message_type": "summary", "status": "success", "message_response": {"summary": {}}},
    {"message_response": {"summary": {"installation_status_summary": {}}}, "status": "success"},
    {"message_response": {"summary": {"installation_status_summary": {"installed": "5"}}}, "status": "success"},
    {"message_response": {"summary": {"installation_status_summary": {"installed": "x", "total": "10"}}}},
    {"message_response": {"summary": {"installation_status_summary": {"installed": "-1", "total": "10"}}}},
    {"total_computers": 10},
]


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_som_no_evidence_is_not_evaluated(fn, key, body):
    value, status, _ = run(fn, body, key)
    assert value is None and status == "error"


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_zero_computers_is_not_evaluated(fn, key):
    value, status, _ = run(fn, som_cloud(0, 0), key)
    assert value is None and status == "error"


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_installed_above_total_is_not_evaluated(fn, key):
    value, status, _ = run(fn, som_cloud(12, 10), key)
    assert value is None and status == "error"


@pytest.mark.parametrize("fn,key", SOM_CHECKS)
def test_patch_bodies_are_not_read_as_som(fn, key):
    value, status, _ = run(fn, patch_summary_body(), key)
    assert value is None and status == "error"


# ------------------------------------------------------------------ patch workflow bodies

def patch_summary_body(installed=900, applicable=1000, missing=100, total=100, healthy=90, critical=0,
                       auto_db_disabled="False"):
    return {"message_type": "summary", "message_version": "1.4", "status": "success", "message_response": {"summary": {
        "patch_summary": {"installed_patches": str(installed), "applicable_patches": str(applicable),
                          "new_patches": "10", "missing_patches": str(missing)},
        "missing_patch_severity_summary": {"critical_count": str(critical), "important_count": "5",
                                           "moderate_count": "3", "low_count": "1", "unrated_count": "0",
                                           "total_count": str(critical + 9)},
        "system_summary": {"total_systems": str(total), "healthy_systems": str(healthy),
                           "highly_vulnerable_systems": "4", "moderately_vulnerable_systems": "6",
                           "health_unknown_systems": "0"},
        "vulnerability_db_summary": {"is_auto_db_update_disabled": auto_db_disabled, "last_db_update_status": "Success"},
    }}}


def health_policy_body():
    return {"message_type": "healthpolicy", "message_version": "1.4", "status": "success", "message_response": {
        "healthpolicy": {"vulnerable": {"critical": "0", "important": "1", "moderate": "2", "low": "3"},
                         "highly_vulnerable": {"critical": "1", "important": "2", "moderate": "3", "low": "0"},
                         "advanced_settings": {"consider_only_approved": "True"}}}}


def merged(summary=None, policy=None):
    body = {}
    if summary is not None:
        body["patchSummary"] = summary
    if policy is not None:
        body["healthPolicy"] = policy
    return body


def deep_merged(summary, policy):
    """What IS deep_merge builds when both steps carry merge: true and no output key."""
    out = copy.deepcopy(summary)
    out["message_response"].update(copy.deepcopy(policy["message_response"]))
    out["message_type"] = policy["message_type"]
    return out


def test_patch_valid_from_keyed_merge():
    value, status, out = run(PATCH, merged(patch_summary_body(), health_policy_body()), "isPatchManagementValid")
    assert (value, status) == (True, "success")
    assert out["transformedResponse"]["healthPolicyRead"] is True
    assert "Health policy thresholds are configured" in out["additionalInfo"]["evaluation"]["additionalFindings"]


def test_patch_valid_from_unkeyed_deep_merge():
    body = deep_merged(patch_summary_body(), health_policy_body())
    assert run(PATCH, body, "isPatchManagementValid")[:2] == (True, "success")


def test_patch_summary_alone_is_evaluated_and_policy_noted_missing():
    value, status, out = run(PATCH, patch_summary_body(), "isPatchManagementValid")
    assert (value, status) == (True, "success")
    assert out["transformedResponse"]["healthPolicyRead"] is False


def test_missing_critical_patch_is_a_real_false():
    value, status, out = run(PATCH, merged(patch_summary_body(critical=3), health_policy_body()),
                             "isPatchManagementValid")
    assert (value, status) == (False, "success")
    assert "3 critical patches are missing" in out["additionalInfo"]["evaluation"]["failReasons"]


def test_low_compliance_and_health_are_real_falses():
    assert run(PATCH, merged(patch_summary_body(installed=500), health_policy_body()),
               "isPatchManagementValid")[:2] == (False, "success")
    assert run(PATCH, merged(patch_summary_body(healthy=50), health_policy_body()),
               "isPatchManagementValid")[:2] == (False, "success")


def test_thresholds_inclusive_at_80():
    assert run(PATCH, patch_summary_body(installed=800, healthy=80), "isPatchManagementValid")[0] is True
    assert run(PATCH, patch_summary_body(installed=799, healthy=80), "isPatchManagementValid")[0] is False


def test_auto_db_update_string_false_is_not_reported_disabled():
    out = run(PATCH, patch_summary_body(auto_db_disabled="False"), "isPatchManagementValid")[2]
    assert "Automatic vulnerability database updates are disabled" not in \
        out["additionalInfo"]["evaluation"]["additionalFindings"]
    out = run(PATCH, patch_summary_body(auto_db_disabled="True"), "isPatchManagementValid")[2]
    assert "Automatic vulnerability database updates are disabled" in \
        out["additionalInfo"]["evaluation"]["additionalFindings"]


def test_health_policy_alone_is_not_evaluated_not_false():
    """Today's live shape: the unmerged workflow keeps only the health policy."""
    for body in (health_policy_body(), merged(None, health_policy_body())):
        value, status, out = run(PATCH, body, "isPatchManagementValid")
        assert value is None and status == "error"
        assert "only the health policy arrived" in out["additionalInfo"]["dataCollection"]["errors"][0]


ERROR_BODY = {"status": "error", "error_code": "1010", "error_description": "User is not authorized to access this API",
              "message_type": "patch", "message_version": "1.4"}


@pytest.mark.parametrize("body", [
    None, {}, [], "", "null",
    ERROR_BODY,
    {"message": "Integrator SRN not available", "status": "Not Available"},
    {"error": True, "message": "401 Unauthorized"},
    merged(ERROR_BODY, health_policy_body()),
    merged(patch_summary_body(), ERROR_BODY),
    merged({}, health_policy_body()),
    {"message_type": "summary", "status": "success", "message_response": {"summary": {}}},
    {"message_response": {"summary": {"patch_summary": {}}}, "status": "success"},
    patch_summary_body(total=0, healthy=0),
    patch_summary_body(applicable=0, installed=0, missing=5),
    som_cloud(90, 100),
])
def test_patch_no_evidence_is_not_evaluated(body):
    value, status, _ = run(PATCH, body, "isPatchManagementValid")
    assert value is None and status == "error"


@pytest.mark.parametrize("field", ["installed_patches", "applicable_patches", "missing_patches"])
def test_missing_patch_count_is_not_evaluated(field):
    body = patch_summary_body()
    del body["message_response"]["summary"]["patch_summary"][field]
    assert run(PATCH, body, "isPatchManagementValid")[0] is None


@pytest.mark.parametrize("section,field", [("system_summary", "total_systems"), ("system_summary", "healthy_systems"),
                                           ("missing_patch_severity_summary", "critical_count")])
def test_missing_system_or_severity_count_is_not_evaluated(section, field):
    body = patch_summary_body()
    del body["message_response"]["summary"][section][field]
    assert run(PATCH, body, "isPatchManagementValid")[0] is None


def test_nothing_applicable_and_nothing_missing_is_compliant():
    assert run(PATCH, patch_summary_body(applicable=0, installed=0, missing=0),
               "isPatchManagementValid")[:2] == (True, "success")
