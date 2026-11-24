"""A generic status, an HTTP code or a bare list of records is not evidence for a criterion.

Every transform below carries its own copy of `affirmative_signal()`. Each copy used to
return True for `{"status": "ok"}`, and most for `{"status": 200}` and any non-empty list,
including the stub the evaluation service substitutes for an empty or non-JSON 2xx body
(`{"status": "Success", "message": "Empty response body"}`). A licence, a logging setting or
behavioural monitoring was then reported as satisfied because a call succeeded.

These tests pin the rule for every copy: such a body is never True, and a None verdict always
carries `dataCollection.status == "error"`, so the evaluator records Not evaluated rather
than a measured fail. Explicit settings still decide, and the audit-logging transforms still
pass on real audit-log records. All bodies are synthetic.
"""
import copy
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

# The Windows Defender (7BC425FA) behavioural, patch and removable-media copies are not listed: #1071 makes them never-measured.
FILES = [
    "0450D686-D997-4E20-B82F-827F61CB8371/confirmedlicensepurchased.py",
    "0C281CE9-8024-4D70-AC85-D923A6B9635C/confirmedlicensepurchased.py",
    "0C281CE9-8024-4D70-AC85-D923A6B9635C/isidpenabled.py",
    "182a41f5-ba7f-42c9-a3cd-7aa8399f5037/confirmedlicensepurchased.py",
    "1BC425FA-0638-4BF1-8194-19E7E4F2F43C/isbehavioralmonitoringvalid.py",
    "1BC425FA-0638-4BF1-8194-19E7E4F2F43C/isidpenabled.py",
    "1BC425FA-0638-4BF1-8194-19E7E4F2F43C/ispatchmanagementenabled.py",
    "1BC425FA-0638-4BF1-8194-19E7E4F2F43C/isremovablemediacontrolled.py",
    "2B2849D8-2FEA-4CAE-9A3C-8B315280752A/confirmedlicensepurchased.py",
    "2BC425FA-0638-4BF1-8194-19E7E4F2F43C/confirmedlicensepurchased.py",
    "2BC425FA-0638-4BF1-8194-19E7E4F2F43C/isidpenabled.py",
    "52beaa98-6ced-4a84-b6d5-faea40e0ffef/confirmedlicensepurchased.py",
    "7BC425FA-0638-4BF1-8194-19E7E4F2F43C/isidpenabled.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/confirmedlicensepurchased.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/confirmlicensepurchased.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/is_mfa_logging_enabled.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/isauditloggingenabled.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/islifecyclemanagementenabled.py",
    "874a78ff-2ca3-4c0e-ab86-19277536ac87/confirmedlicensepurchased.py",
    "BBC425FA-0638-4BF1-8194-19E7E4F2F43C/confirmedlicensepurchased.py",
    # Out per #1065 (reads no self-named key): BBC425FA four checks, NinjaOne SSO, Avanan logging.
    "a6b871e6-de13-41fa-8636-81a3b6f315f4/asm_transform.py",
    "a6b871e6-de13-41fa-8636-81a3b6f315f4/confirmedlicensepurchased.py",
    "backups/azure/confirmedlicensepurchased.py",
    "backups/datto/issamlenforced.py",
    "cac4b80f-a930-415e-b1e3-de285fe78452/confirmedlicensepurchased.py",
    "cac4b80f-a930-415e-b1e3-de285fe78452/isbehavioralmonitoringvalid.py",
    "cac4b80f-a930-415e-b1e3-de285fe78452/ispatchmanagementenabled.py",
    "cac4b80f-a930-415e-b1e3-de285fe78452/isremovablemediacontrolled.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/confirmedlicensepurchased.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/is_mfa_logging_enabled.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/isauditloggingenabled.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/islifecyclemanagementenabled.py",
    "emailsecurity/avanan/confirmedlicensepurchased.py",
    "epp/addigy/confirmedlicensepurchased.py",
    "epp/liongard/confirmedlicensepurchased.py",
    "iam/beyondtrust-pra/confirmedlicensepurchased.py",
    "iam/beyondtrust/confirmedlicensepurchased.py",
    "iam/beyondtrust/issessionmonitoringenabled.py",
    "identity-and-access-management/beyondtrust/confirmedLicensePurchased.py",
    "identity-and-access-management/beyondtrust/isSessionMonitoringEnabled.py",
    "mfa/azure/confirmlicensepurchased.py",
    "mfa/azure/isauditloggingenabled.py",
    "mfa/azure/islifecyclemanagementenabled.py",
    "mfa/azure/ismfaloggingenabled.py",
    "sase/zscaler/confirmedlicensepurchased.py",
    "threatintelligence/horizon3/confirmedlicensepurchased.py",
]

AUDIT_LOG_FILES = [
    "86ded564-522a-4c9b-9106-365e4cbdec7d/is_mfa_logging_enabled.py",
    "86ded564-522a-4c9b-9106-365e4cbdec7d/isauditloggingenabled.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/is_mfa_logging_enabled.py",
    "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/isauditloggingenabled.py",
    "mfa/azure/isauditloggingenabled.py",
    "mfa/azure/ismfaloggingenabled.py",
]

# Files whose own vendor rule, outside affirmative_signal, already reads a bare list or a
# `data` object as evidence (an authenticated appliance answer, a permissions or
# environments list). That is a per-vendor decision this change leaves alone, so those
# shapes are not generated for them; every other generic body is still judged.
OWN_LIST_RULE = {
    "epp/addigy/confirmedlicensepurchased.py": {"data_object"},
    "epp/liongard/confirmedlicensepurchased.py": {"bare_list", "items_list", "data_object", "endpoint_list"},
    "iam/beyondtrust-pra/confirmedlicensepurchased.py": {"bare_list"},
    "iam/beyondtrust/confirmedlicensepurchased.py": {"bare_list"},
    "iam/beyondtrust/issessionmonitoringenabled.py": {"bare_list"},
    "identity-and-access-management/beyondtrust/confirmedLicensePurchased.py": {"bare_list"},
    "identity-and-access-management/beyondtrust/isSessionMonitoringEnabled.py": {"bare_list"},
}

GENERIC = {
    "status_ok": {"status": "ok"},
    "status_200": {"status": 200},
    "status_success": {"status": "success"},
    "empty_body_stub": {"status": "Success", "message": "Empty response body"},
    "non_json_stub": {"status": "Success", "message": "Streaming Response"},
    "wrapped_status": {"response": {"status": "ok"}},
    "message_and_status": {"message": "done", "status": "success"},
    "state_active": {"state": "active"},
    "bare_list": [{"id": "1"}],
    "items_list": {"items": [{"id": "1"}]},
    "value_list": {"@odata.context": "x", "value": [{"id": "1"}]},
    "data_object": {"data": {"id": "1"}},
    "unrecognised": {"kind": "account", "name": "example"},
    # Vendor shapes these transforms are wired to. None of them says anything about the
    # criterion itself: an org object, a SKU list, a user list, an endpoint list.
    "org_object": {"id": "00o0000000000000000", "subdomain": "example", "status": "ACTIVE",
                   "created": "2020-01-01T00:00:00.000Z", "_links": {}},
    "sku_list": {"@odata.context": "x", "value": [{"skuPartNumber": "EXAMPLE_FREE", "capabilityStatus": "Enabled",
                                                   "prepaidUnits": {"enabled": 10000}, "consumedUnits": 1}]},
    "user_list": {"@odata.context": "x", "value": [{"id": "1", "userPrincipalName": "a@example.com",
                                                    "accountEnabled": True}]},
    "endpoint_list": {"items": [{"id": "1", "type": "computer", "hostname": "host-1",
                                 "health": {"overall": "good"}}], "pages": {"current": 1}},
}

OKTA_EVENT = {"uuid": "00000000-0000-4000-8000-000000000001", "published": "2026-01-01T00:00:00.000Z",
              "eventType": "user.session.start", "outcome": {"result": "SUCCESS"}}
GRAPH_AUDIT = {"id": "Directory_00000000", "activityDateTime": "2026-01-01T00:00:00Z",
               "activityDisplayName": "Update user", "category": "UserManagement"}

_MODULES = {}


def load(rel):
    if rel not in _MODULES:
        name = "affirm_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
        spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, rel))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[rel] = module
    return _MODULES[rel]


def run(rel, body):
    out = load(rel).transform(copy.deepcopy(body))
    verdict = out.get("transformedResponse", out)
    criteria = {k: v for k, v in verdict.items()
                if k.startswith(("is", "are", "confirmed")) and not k.endswith("Count")}
    assert criteria, out
    return out, criteria


def assert_not_true(out, criteria):
    for key, value in criteria.items():
        assert value is not True, (key, out)
        if value is None:
            assert out["additionalInfo"]["dataCollection"]["status"] == "error", out
            assert out["additionalInfo"]["dataCollection"]["errors"], out


CASES = [(rel, shape) for rel in FILES for shape in sorted(GENERIC)
         if shape not in OWN_LIST_RULE.get(rel, ())]


@pytest.mark.parametrize("rel,shape", CASES)
def test_generic_body_is_never_a_pass(rel, shape):
    out, criteria = run(rel, GENERIC[shape])
    assert_not_true(out, criteria)


@pytest.mark.parametrize("rel", FILES)
def test_explicit_on_setting_still_passes(rel):
    _, criteria = run(rel, {"enabled": True})
    assert all(v is True for v in criteria.values()), criteria


@pytest.mark.parametrize("rel", FILES)
def test_explicit_off_is_never_a_pass(rel):
    for body in ({"enabled": False}, {"status": "disabled"}, {"status": "inactive", "items": [{"id": "1"}]}):
        if rel in OWN_LIST_RULE and "items_list" in OWN_LIST_RULE[rel]:
            continue
        out, criteria = run(rel, body)
        assert_not_true(out, criteria)


@pytest.mark.parametrize("rel", AUDIT_LOG_FILES)
def test_audit_log_records_still_pass(rel):
    bodies = [{"@odata.context": "x", "value": [GRAPH_AUDIT]}]
    if rel != "d9b6f27a-2e67-4b55-a09e-0784c5de9abd/isauditloggingenabled.py":  # Graph only: no list form
        bodies.append([OKTA_EVENT])
    for body in bodies:
        out, criteria = run(rel, body)
        assert all(v is True for v in criteria.values()), out
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("rel", AUDIT_LOG_FILES)
def test_audit_log_needs_event_fields(rel):
    # A record with a timestamp but no event type, or the reverse, is not an audit event.
    for record in ({"published": "2026-01-01T00:00:00.000Z"}, {"activityDisplayName": "Update user"}):
        out, criteria = run(rel, {"value": [record]})
        assert all(v is None for v in criteria.values()), out
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("rel", AUDIT_LOG_FILES)
def test_empty_audit_log_stays_a_measured_fail(rel):
    out, criteria = run(rel, {"@odata.context": "x", "value": []})
    assert all(v is False for v in criteria.values()), out


# A body that states the criterion explicitly is a measurement, whatever the helper says about
# the rest of it. The helper's None ("no evidence") must not turn an explicit OFF into Not
# evaluated, and a None sibling must not hide an explicit primary verdict.

def dc_status(out):
    return out.get("additionalInfo", {}).get("dataCollection", {}).get("status", "success")


@pytest.mark.parametrize("body", [
    {"isSAMLEnforced": False},
    {"samlEnabled": False},
    {"ssoEnabled": False},
    {"sso": {"enforced": False}},
    {"isSAMLEnforced": False, "status": "ok"},
])
def test_datto_saml_explicit_off_is_a_measured_fail(body):
    out, criteria = run("backups/datto/issamlenforced.py", body)
    assert criteria == {"isSAMLEnforced": False}, out
    assert dc_status(out) == "success", out


@pytest.mark.parametrize("body", [
    {"isSAMLEnforced": True},
    {"sso": {"enforced": True}},
    {"isSAMLEnforced": False, "ssoEnabled": True},
])
def test_datto_saml_explicit_on_passes(body):
    out, criteria = run("backups/datto/issamlenforced.py", body)
    assert criteria == {"isSAMLEnforced": True}, out
    assert dc_status(out) == "success", out


PRIMARY_WITH_SIBLING = {
    "isidpenabled.py": ("isSSOEnabled", "isSSOEnabledMDR"),
    "ispatchmanagementenabled.py": ("isPatchManagementEnabled", "isPatchManagementValid"),
}
SIBLING_CASES = [(rel, value) for rel in FILES if rel.rsplit("/", 1)[-1] in PRIMARY_WITH_SIBLING
                 for value in (True, False)]


@pytest.mark.parametrize("rel,value", SIBLING_CASES)
def test_explicit_primary_without_sibling_keeps_its_verdict(rel, value):
    primary, sibling = PRIMARY_WITH_SIBLING[rel.rsplit("/", 1)[-1]]
    out, criteria = run(rel, {primary: value})
    assert criteria[primary] is value, out
    assert dc_status(out) == "success", out
    # The body says nothing about the sibling, so it is never a pass on the primary's word.
    assert criteria[sibling] is False, out


@pytest.mark.parametrize("value", [True, False])
def test_asm_explicit_flag_without_lists_stays_measured(value):
    out, criteria = run("a6b871e6-de13-41fa-8636-81a3b6f315f4/asm_transform.py", {"isASMEnabled": value})
    assert criteria["isASMEnabled"] is value, out
    assert criteria["isASMLoggingEnabled"] is None, out
    assert dc_status(out) == "success", out
    reasons = out["additionalInfo"]["evaluation"]["passReasons" if value else "failReasons"]
    assert any("Attack Surface Management" in r for r in reasons), out


@pytest.mark.parametrize("rel,value", SIBLING_CASES)
def test_sibling_alone_leaves_the_primary_not_evaluated(rel, value):
    # The file answers the primary criterion; a body that names only the secondary finding
    # has no evidence for it, so the whole response routes to Not evaluated, never a pass.
    primary, sibling = PRIMARY_WITH_SIBLING[rel.rsplit("/", 1)[-1]]
    out, criteria = run(rel, {sibling: value})
    assert criteria[primary] is None, out
    assert dc_status(out) == "error", out
