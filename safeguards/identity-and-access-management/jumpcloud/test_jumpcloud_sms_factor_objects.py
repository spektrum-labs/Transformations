"""JumpCloud isSmsAuthenticationDisabled reads mfaFactors as OBJECTS (2026-10-01).

GET /api/v2/authn/policies, schema AuthnPolicyObligations.mfaFactors: [{"type": "SMS_OTP" | ...}]
(https://docs.jumpcloud.com/api/2.0/index.yaml). The previous version matched string entries only, so it never
saw {"type": "SMS_OTP"} and passed; it also passed on an empty factor list ("All Enabled"). Fixtures are synthetic.
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEY = "isSmsAuthenticationDisabled"


def load():
    spec = importlib.util.spec_from_file_location("jc_sms_" + KEY, HERE / (KEY + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(body):
    out = load().transform(body)
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


def policy(name="p", disabled=False, monitor=False, action="allow", mfa_required=True, factors=("TOTP", "WEBAUTHN"),
           ptype="user_portal"):
    obligations = {"mfa": {"required": mfa_required}, "userVerification": {"requirement": "none"}}
    if factors is not None:
        obligations["mfaFactors"] = [{"type": f} for f in factors]
    return {"id": name, "name": name, "type": ptype, "disabled": disabled, "monitorOnly": monitor,
            "effect": {"action": action, "obligations": obligations},
            "targets": {"resources": [{"type": ptype}], "userGroups": {"inclusions": ["g1"], "exclusions": []}},
            "conditions": {}}


def stored_shape():
    """The shape stored for a real tenant on 30 Sep: one enforced user-portal policy, MFA required,
    mfaFactors [] ('All Enabled'), booleans as strings."""
    p = policy("portal", factors=())
    p["disabled"], p["monitorOnly"] = "False", "False"
    p["effect"]["obligations"]["mfa"]["required"] = "True"
    return [p]


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "empty_list": [],
    "auth_401": {"message": "Unauthorized", "status": 401},
    "is_403": {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"},
    "error": {"error": "invalid api key"},
    "unrelated": {"items": [{"id": 1}]},
    "not_policies": [{"id": "u1", "username": "someone"}],
    "partial_read": {"results": [policy()], "totalCount": 3},
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(name):
    assert run(NO_EVIDENCE[name]) == (None, "error")


def test_stored_shape_with_empty_factor_list_is_unevaluated():
    # The old transform passed this body. "All Enabled" cannot show whether SMS is allowed.
    assert run(stored_shape()) == (None, "error")
    assert run({"results": stored_shape(), "totalCount": 1}) == (None, "error")


def test_missing_factor_list_is_unevaluated():
    assert run([policy(factors=None)]) == (None, "error")


def test_sms_object_factor_fails():
    assert run([policy(factors=("SMS_OTP",))]) == (False, "success")
    assert run([policy(factors=("WEBAUTHN", "SMS_OTP"))]) == (False, "success")


def test_sms_fails_even_when_another_policy_is_undecided():
    assert run([policy("a", factors=()), policy("b", factors=("TOTP", "SMS_OTP"))]) == (False, "success")


def test_explicit_non_sms_factors_pass():
    assert run([policy(factors=("TOTP", "PUSH", "WEBAUTHN", "DUO"))]) == (True, "success")
    assert run([policy("portal"), policy("admin", ptype="admin_portal", factors=("WEBAUTHN",))]) == (True, "success")


def test_one_all_enabled_policy_blocks_a_pass():
    assert run([policy("a"), policy("b", factors=())]) == (None, "error")


def test_undocumented_factor_type_is_unevaluated():
    assert run([policy(factors=("TOTP", "NEW_FACTOR"))]) == (None, "error")


def test_only_enforced_mfa_policies_are_judged():
    body = [policy("ok"), policy("off", disabled=True, factors=("SMS_OTP",)), policy("trial", monitor=True, factors=("SMS_OTP",)),
            policy("block", action="deny", factors=("SMS_OTP",)), policy("ldap", ptype="ldap", mfa_required=False, factors=None)]
    assert run(body) == (True, "success")


def test_no_enforced_mfa_policy_is_unevaluated():
    assert run([policy(disabled=True)]) == (None, "error")
    assert run([policy(monitor=True)]) == (None, "error")
    assert run([policy(mfa_required=False, factors=None)]) == (None, "error")
    assert run([policy(action="deny")]) == (None, "error")


def test_unreadable_fields_are_unevaluated():
    assert run([policy(disabled="maybe")]) == (None, "error")
    assert run([policy(mfa_required="yes")]) == (None, "error")
    assert run([policy(action="unknown")]) == (None, "error")


def test_string_booleans_are_read():
    p = policy()
    p["disabled"], p["monitorOnly"] = "False", "False"
    p["effect"]["obligations"]["mfa"]["required"] = "True"
    assert run([p]) == (True, "success")


def test_envelopes_agree():
    body = [policy(factors=("SMS_OTP",))]
    assert run(body) == run({"results": body, "totalCount": 1}) == run(json.dumps(body)) == run({"apiResponse": body})
