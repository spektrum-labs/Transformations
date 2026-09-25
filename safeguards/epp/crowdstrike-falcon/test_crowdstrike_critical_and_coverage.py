"""CrowdStrike isEPPEnabledForCriticalSystems (per-platform) and requiredCoveragePercentage
(truncation + reduced_functionality_mode "yes").

Real payloads (2026-09-25, redacted to the fields read):
  * a Falcon EPP tenant's prevention policies: Falcon Complete layout, MeasuredWin/Lin/Mac on
    "Servers", enabled stored as the string "True";
  * an XDR tenant's getAssetDetails, unpaged: meta.pagination total 1511, 100 devices returned,
    one of them reduced_functionality_mode "yes".
Real, flipped, empty, None, error."""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("cs_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CRIT = load("isEPPEnabledForCriticalSystems")
COV = load("requiredCoveragePercentage")
POLICIES = json.loads((HERE / "fixtures" / "falcon_complete_prevention_policies_real_2026-09-25.json").read_text())
DEVICES = json.loads((HERE / "fixtures" / "xdr_devices_unpaged_real_2026-09-25.json").read_text())
ERROR = {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"}


def crit(body):
    out = CRIT.transform(body)
    return out["transformedResponse"]["isEPPEnabledForCriticalSystems"], out["additionalInfo"]["dataCollection"]["status"]


def cov(body):
    out = COV.transform(body)
    return out["transformedResponse"]["requiredCoveragePercentage"], out["additionalInfo"]["dataCollection"]["status"]


def set_enabled(body, name, value):
    for p in body["resources"]:
        if p["name"] == name:
            p["enabled"] = value
            return body
    raise KeyError(name)


def test_critical_real_policies_pass():
    assert crit(POLICIES) == (True, "success")
    assert crit(json.dumps(POLICIES)) == (True, "success")
    assert crit({"apiResponse": POLICIES}) == (True, "success")


def test_critical_disabled_windows_policy_on_servers_fails_although_linux_is_enabled():
    for disabled in ("False", False):
        body = set_enabled(copy.deepcopy(POLICIES), "MeasuredWin", disabled)
        assert crit(body) == (False, "success"), disabled


def test_critical_disabled_workstation_policy_does_not_matter():
    body = set_enabled(copy.deepcopy(POLICIES), "ActiveWin", "False")
    assert crit(body) == (True, "success")


def test_critical_no_critical_group_fails():
    body = copy.deepcopy(POLICIES)
    for p in body["resources"]:
        p["groups"] = [g for g in p["groups"] if g["name"] != "Servers"]
    assert crit(body) == (False, "success")


def test_critical_dc_is_a_word_not_a_substring():
    assert CRIT.is_critical_group_name("DC Hosts")
    assert CRIT.is_critical_group_name("site-dc-01")
    assert not CRIT.is_critical_group_name("Hardcore Testers")


def test_critical_fail_closed_inputs():
    for body in ({}, None, "", "{}", ERROR, {"resources": "x"}, {"errors": [{"code": 403}], "resources": []}):
        assert crit(body) == (False, "error"), body
    truncated = copy.deepcopy(POLICIES)
    truncated["meta"] = {"pagination": {"total": "40"}}
    assert crit(truncated) == (False, "error")


def test_coverage_real_unpaged_sample_is_not_measured():
    assert cov(DEVICES) == (0, "error")


def test_coverage_complete_list_counts_rfm_yes_as_inactive():
    body = copy.deepcopy(DEVICES)
    body["meta"]["pagination"]["total"] = str(len(body["resources"]))
    assert cov(body) == (99.0, "success")  # 99 normal/"no", 1 normal/"yes"
    flipped = copy.deepcopy(body)
    for d in flipped["resources"]:
        d["reduced_functionality_mode"] = "no"
    assert cov(flipped) == (100.0, "success")


def test_coverage_merged_truncated_response_is_not_measured():
    body = copy.deepcopy(DEVICES)
    body["meta"]["pagination"] = {"total": "100", "truncated": True, "scannedCount": 100}
    assert cov(body) == (0, "error")


def test_coverage_fail_closed_inputs():
    for body in (ERROR, {"status": "Error", "message": "x"}):
        assert cov(body) == (0, "error"), body
    for body in ({}, None, "{}", {"resources": []}):
        value, _ = cov(body)
        assert value == 0, body
