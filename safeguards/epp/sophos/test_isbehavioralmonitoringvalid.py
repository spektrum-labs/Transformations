"""Sophos EDR isBehavioralMonitoringValid reads the Threat Protection policies (2026-10-01).

Replaces the shared 1BC425FA transform for Sophos EDR, which passed on any non-empty
endpoint list. Fixtures follow the documented Sophos Central shape for
GET /endpoint/v1/policies?policyType=threat-protection&pageTotal=true.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEY = "isBehavioralMonitoringValid"
ON_ACCESS = "endpoint.threat-protection.malware-protection.on-access.enabled"
BEHAVIOURAL = "endpoint.threat-protection.malware-protection.behavioral-detection.enabled"
HIPS = "endpoint.threat-protection.malware-protection.hips-detection.enabled"


def load():
    spec = importlib.util.spec_from_file_location("sophos_bmv", HERE / "isbehavioralmonitoringvalid.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load()


def setting(value):
    return {"value": value, "recommendedValue": True, "locked": False}


def tp_settings(on_access=True, behavioural=True, hips=True):
    settings = {
        "endpoint.threat-protection.malware-protection.deep-learning.enabled": setting(True),
        "endpoint.threat-protection.malware-protection.live-protection.enabled": setting(True),
        "endpoint.threat-protection.malware-protection.amsi-protection.enabled": setting(True),
        "endpoint.threat-protection.network-protection.c2-detection.enabled": setting(True),
        "endpoint.threat-protection.exploit-mitigation.cryptoguard.enabled": setting(True),
    }
    if on_access is not None:
        settings[ON_ACCESS] = setting(on_access)
    if behavioural is not None:
        settings[BEHAVIOURAL] = setting(behavioural)
    if hips is not None:
        settings[HIPS] = setting(hips)
    return settings


def policy(name, priority, enabled=True, applies=None, **kw):
    return {
        "id": "b1d2c3e4-0000-4000-8000-%012d" % priority,
        "name": name,
        "type": "threat-protection",
        "priority": priority,
        "enabled": enabled,
        "createdAt": "2025-02-11T14:03:22.110Z",
        "updatedAt": "2026-08-30T09:41:07.552Z",
        "settings": tp_settings(**kw),
        "appliesTo": applies if applies is not None else (
            {"allUsers": True} if priority == 0 else {"endpointGroups": [{"id": "g-servers-01", "name": "Finance"}]}),
    }


def body(*items, total=1):
    return {"items": list(items), "pages": {"current": 1, "size": 50, "total": total, "items": len(items), "maxSize": 200}}


def run(payload):
    out = MOD.transform(payload)
    return out["transformedResponse"][KEY], out


GOOD = body(policy("Base Policy", 0), policy("Finance laptops", 1))


def test_happy_path_passes():
    value, out = run(GOOD)
    assert value is True
    info = out["additionalInfo"]
    assert info["metadata"]["schemaVersion"] == "2.0"
    assert set(info) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
    assert out["transformedResponse"]["policiesJudged"] == 2


def test_string_and_bytes_and_wrapped_inputs_pass():
    assert run(json.dumps(GOOD))[0] is True
    assert run(json.dumps(GOOD).encode("utf-8"))[0] is True
    assert run({"response": GOOD})[0] is True
    assert run({"data": GOOD, "validation": {"status": "passed", "errors": [], "warnings": []}})[0] is True


def test_behaviour_detection_off_in_base_fails():
    value, out = run(body(policy("Base Policy", 0, behavioural=False)))
    assert value is False
    assert "Detect malicious behavior is off" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_behaviour_detection_off_beats_hips_on():
    assert run(body(policy("Base Policy", 0, behavioural=False, hips=True)))[0] is False


def test_real_time_scanning_off_fails():
    assert run(body(policy("Base Policy", 0, on_access=False)))[0] is False


def test_assigned_override_policy_with_detection_off_fails():
    assert run(body(policy("Base Policy", 0), policy("Dev workstations", 1, behavioural=False)))[0] is False


def test_unassigned_or_disabled_override_is_not_judged():
    unassigned = policy("Spare", 2, behavioural=False,
                        applies={"users": [], "userGroups": [], "endpoints": [], "endpointGroups": []})
    disabled = policy("Old", 3, enabled=False, behavioural=False)
    value, out = run(body(policy("Base Policy", 0), unassigned, disabled))
    assert value is True
    assert out["transformedResponse"]["policiesNotApplied"] == 2


def test_no_base_policy_fails():
    assert run(body(policy("Finance laptops", 1)))[0] is False


def test_no_threat_protection_policy_fails():
    other = {"id": "x", "name": "Base Policy", "type": "peripheral-control", "priority": 0,
             "enabled": True, "settings": {"endpoint.peripheral-control.enabled": setting(True)}}
    assert run(body(other))[0] is False
    assert run(body())[0] is False


def test_missing_settings_are_not_read_at_default():
    assert run(body(policy("Base Policy", 0, on_access=None)))[0] is False
    assert run(body(policy("Base Policy", 0, behavioural=None, hips=None)))[0] is False
    no_settings = policy("Base Policy", 0)
    no_settings["settings"] = {}
    assert run(body(no_settings))[0] is False


def test_legacy_hips_only_is_accepted_and_reported():
    value, out = run(body(policy("Base Policy", 0, behavioural=None, hips=True)))
    assert value is True
    assert out["transformedResponse"]["policiesOnLegacyHips"] == ["Base Policy"]
    assert run(body(policy("Base Policy", 0, behavioural=None, hips=False)))[0] is False


def test_multi_page_fails_closed():
    value, out = run(body(policy("Base Policy", 0), total=3))
    assert value is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_full_first_page_without_total_fails_closed():
    items = [policy("Base Policy", 0)] + [policy("P%d" % i, i) for i in range(1, 50)]
    no_total = {"items": items, "pages": {"current": 1, "size": 50, "maxSize": 200}}
    assert run(no_total)[0] is False
    no_total["items"] = items[:3]
    assert run(no_total)[0] is True


def test_unfiltered_getpolicies_body_judges_only_threat_protection():
    mixed = copy.deepcopy(GOOD)
    mixed["items"].append({"id": "p", "name": "Base Policy", "type": "peripheral-control", "priority": 0,
                           "enabled": True, "settings": {}})
    assert run(mixed)[0] is True


@pytest.mark.parametrize("payload", [
    None, {}, "{}", "", b"", [], "not json {",
    {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}, {"items": [{"id": 1}]},
    {"error": "Unauthorized", "message": "Invalid token"},
    {"statusCode": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 403, "message": "Forbidden"}},
    {"status": 500},
    {"items": [{"id": "e1", "hostname": "WS-01", "health": {"overall": "good"}}]},
    {"isBehavioralMonitoringValid": True},
    {"data": {}, "validation": {"status": "failed", "errors": ["schema"], "warnings": []}},
])
def test_no_evidence_fails_closed(payload):
    value, out = run(payload)
    assert value is False


def test_endpoint_inventory_that_passed_the_old_transform_now_fails():
    endpoints = {"items": [{"id": "e1", "type": "computer", "hostname": "TRB-WS-014",
                            "health": {"overall": "bad", "threats": {"status": "bad"},
                                       "services": {"status": "bad"}}}],
                 "pages": {"fromKey": None, "nextKey": None, "size": 50, "maxSize": 500}}
    assert run(endpoints)[0] is False


def test_transform_crash_is_reported_on_the_channel_the_evaluator_reads(monkeypatch):
    """An unexpected exception must read Not evaluated, not a measured answer.

    The evaluator reads additionalInfo.dataCollection.status only, which create_response
    derives from api_errors. Reporting the crash under transformation alone left it "success".
    """
    def boom(_data):
        raise RuntimeError("synthetic crash")

    monkeypatch.setattr(MOD, "policy_items", boom)
    out = MOD.transform(GOOD)
    info = out["additionalInfo"]
    assert out["transformedResponse"][KEY] is False
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"] == ["Transformation error: synthetic crash"]
    assert info["transformation"]["status"] == "error"
    assert info["transformation"]["errors"] == ["synthetic crash"]


def test_a_clean_run_still_reports_data_collection_success():
    assert run(GOOD)[1]["additionalInfo"]["dataCollection"]["status"] == "success"
