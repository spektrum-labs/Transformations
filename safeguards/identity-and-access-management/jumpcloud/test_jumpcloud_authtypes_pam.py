"""JumpCloud authTypesAllowed and isPAMEnabled (2026-10-01).

authTypesAllowed reads effect.obligations.mfaFactors[].type on enforced authentication policies
(GET /api/v2/authn/policies, schema AuthnPolicyObligations). isPAMEnabled reads isPam from
GET /api/v2/privileged-access/status (schema jumpcloud.privileged_access.GetPasswordVaultStatusResponse).
Spec: https://docs.jumpcloud.com/api/2.0/index.yaml. Fixtures are synthetic.
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent


def load(key):
    spec = importlib.util.spec_from_file_location("jc2_" + key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(key, body):
    out = load(key).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def policy(name="p", disabled=False, monitor=False, action="allow", mfa_required=True, factors=("WEBAUTHN",),
           ptype="user_portal"):
    obligations = {"mfa": {"required": mfa_required}, "userVerification": {"requirement": "none"}}
    if factors is not None:
        obligations["mfaFactors"] = [{"type": f} for f in factors]
    return {"id": name, "name": name, "type": ptype, "disabled": disabled, "monitorOnly": monitor,
            "effect": {"action": action, "obligations": obligations},
            "targets": {"resources": [{"type": ptype}], "userGroups": {"inclusions": ["g1"], "exclusions": []}},
            "conditions": {}}


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "auth_401": {"message": "Unauthorized", "status": 401},
    "is_403": {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"},
    "error": {"error": "invalid api key"},
    "unrelated": {"items": [{"id": 1}]},
    "not_policies": [{"id": "u1", "username": "someone"}],
}


# ---- authTypesAllowed ---------------------------------------------------------------------------------
A = "authTypesAllowed"


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_auth_types_no_evidence_is_unevaluated(name):
    assert run(A, NO_EVIDENCE[name]) == (None, "error")


def test_auth_types_no_enforced_policy_is_unevaluated():
    assert run(A, []) == (None, "error")
    assert run(A, [policy(disabled=True)]) == (None, "error")
    assert run(A, [policy(monitor=True)]) == (None, "error")
    assert run(A, [policy(action="deny")]) == (None, "error")


def test_auth_types_webauthn_only_passes():
    assert run(A, [policy("portal"), policy("admin", ptype="admin_portal")]) == (True, "success")


@pytest.mark.parametrize("factors", [("TOTP",), ("PUSH",), ("DUO",), ("SMS_OTP",), ("WEBAUTHN", "TOTP")])
def test_auth_types_phishable_factor_fails(factors):
    assert run(A, [policy(factors=factors)]) == (False, "success")


def test_auth_types_no_mfa_required_fails():
    assert run(A, [policy(mfa_required=False, factors=None)]) == (False, "success")
    assert run(A, [policy(), policy("ldap", ptype="ldap", mfa_required=False, factors=None)]) == (False, "success")


def test_auth_types_all_enabled_is_unevaluated():
    # No explicit factor list means "All Enabled": the organisation's enabled factors are not in the API.
    assert run(A, [policy(factors=None)]) == (None, "error")
    assert run(A, [policy(factors=())]) == (None, "error")
    assert run(A, [policy(), policy("other", factors=None)]) == (None, "error")


def test_auth_types_undocumented_factor_is_unevaluated():
    assert run(A, [policy(factors=("DURT",))]) == (None, "error")
    assert run(A, [policy(factors=("WEBAUTHN", "NEW_FACTOR"))]) == (None, "error")


def test_auth_types_definite_failure_wins_over_unreadable():
    assert run(A, [policy(factors=None), policy("weak", factors=("TOTP",))]) == (False, "success")


def test_auth_types_ignores_disabled_monitor_and_deny_policies():
    body = [policy(), policy("old", disabled=True, factors=("SMS_OTP",)), policy("trial", monitor=True, factors=("TOTP",)),
            policy("block", action="deny", mfa_required=False, factors=None)]
    assert run(A, body) == (True, "success")


def test_auth_types_unreadable_booleans_are_unevaluated():
    assert run(A, [policy(disabled="maybe")]) == (None, "error")
    assert run(A, [policy(mfa_required="yes")]) == (None, "error")


def test_auth_types_string_booleans_are_read():
    body = [policy(disabled="False", monitor="False", mfa_required="True")]
    assert run(A, body) == (True, "success")


def test_auth_types_partial_read_is_unevaluated():
    assert run(A, {"results": [policy()], "totalCount": 2}) == (None, "error")


def test_auth_types_envelopes_agree():
    body = [policy()]
    assert run(A, body) == run(A, {"results": body, "totalCount": 1}) == run(A, json.dumps(body))
    assert run(A, {"apiResponse": body}) == (True, "success")


def test_auth_types_returns_a_boolean_for_is_equals():
    out = load(A).transform([policy()])
    assert out["transformedResponse"][A] is True


# ---- isPAMEnabled -------------------------------------------------------------------------------------
P = "isPAMEnabled"


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_pam_no_evidence_is_unevaluated(name):
    assert run(P, NO_EVIDENCE[name]) == (None, "error")


def test_pam_activated_passes():
    assert run(P, {"isActive": True, "isPam": True, "isPwm": False}) == (True, "success")
    assert run(P, {"isPam": True}) == (True, "success")


def test_pam_not_activated_fails_even_with_password_vault():
    assert run(P, {"isActive": True, "isPam": False, "isPwm": True}) == (False, "success")
    assert run(P, {"isActive": False, "isPam": False, "isPwm": False}) == (False, "success")


def test_pam_unreadable_or_contradictory_is_unevaluated():
    assert run(P, {"isPam": None}) == (None, "error")
    assert run(P, {"isPam": "maybe"}) == (None, "error")
    assert run(P, {"isActive": False, "isPam": True}) == (None, "error")
    assert run(P, {"isPwm": True, "isActive": True}) == (None, "error")


def test_pam_envelopes_and_string_booleans_agree():
    body = {"isActive": True, "isPam": True, "isPwm": False}
    assert run(P, {"apiResponse": body}) == run(P, json.dumps(body)) == run(P, {"isActive": "True", "isPam": "True"})


# ---- isPAMEnabled output contract -----------------------------------------------------------------------
def _pam_outputs():
    mod = load(P)
    bodies = [{"isActive": True, "isPam": True, "isPwm": False},     # True
              {"isActive": True, "isPam": False, "isPwm": True},     # False
              {"isActive": False, "isPam": True},                    # None, contradictory
              {}, None, {"error": {"code": 403}}]                    # None, no evidence
    return [mod.transform(b) for b in bodies]


def test_pam_emits_only_the_criterion_and_never_a_vendor_field():
    for out in _pam_outputs():
        assert set(out["transformedResponse"]) == {P}
        assert not {"isPam", "isPwm", "isActive"} & set(out["transformedResponse"])


def test_pam_summary_keys_are_renamed_and_carry_the_vendor_values():
    out = load(P).transform({"isActive": True, "isPam": False, "isPwm": True})
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary == {"privilegedAccessActivated": False, "tenantActive": True, "passwordVaultActivated": True}


def test_pam_does_not_read_its_own_answer_out_of_the_body():
    import sys
    tools = HERE.parents[2] / "tools"
    sys.path.insert(0, str(tools))
    try:
        from check_no_self_answer import answered_and_read
    finally:
        sys.path.remove(str(tools))
    assert answered_and_read((HERE / (P + ".py")).read_text()) == set()
