"""JumpCloud transforms fail closed (2026-09-29).

A body that proves nothing (null, an error envelope, unrelated JSON, a partial user read) must
return the key as None with dataCollection.status "error", which reads as Unevaluated. Real
bodies still evaluate, and the two MFA-enrollment fixes count only real enrollment evidence.
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent
USER_KEYS = [
    "desktopAuthenticatorEnrollmentPercentage", "inactiveMfaFactorsCount", "isLifeCycleManagementEnabled",
    "isMFAEnabled", "lockedOutUsersCount", "mfaDeviceEnrollmentPercentage", "mfaEnforcementCoveragePercentage",
    "smsFactorEnabledUsersCount", "suspendedUsersCount", "webAuthnCredentialAdoptionPercentage",
]
POLICY_KEYS = [
    "areConditionalAccessPoliciesConfigured", "authTypesAllowed", "isAdminMFAPhishingResistant",
    "isMFAConfiguredForSecurityAdmins", "isMFAEnforced", "isMFAEnforcedForUsers", "isSmsAuthenticationDisabled",
    "isStrongAuthRequired", "passwordOnlyAuthPolicyRulesCount", "relyingPartyTrustsWithoutAccessControlPolicyCount",
]
OTHER_KEYS = ["isSSOEnabled", "isIdentityProfileSyncEnabled"]
ALL_KEYS = USER_KEYS + POLICY_KEYS + OTHER_KEYS

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "auth_401": {"message": "Unauthorized", "status": 401},
    "error": {"error": "invalid api key"},
    "unrelated": {"items": [{"id": 1}]},
}


def load(key):
    spec = importlib.util.spec_from_file_location("jc_" + key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(key, body):
    out = load(key).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def user(**kw):
    u = {"_id": kw.pop("_id", "u"), "username": "u", "state": "ACTIVATED", "suspended": False,
         "totp_enabled": False, "enable_user_portal_multifactor": False,
         "mfa": {"configured": False, "exclusion": False},
         "mfaEnrollment": {"overallStatus": "NOT_ENROLLED", "totpStatus": "NOT_ENROLLED",
                           "webAuthnStatus": "NOT_ENROLLED", "pushStatus": "NOT_ENROLLED"}}
    u.update(kw)
    return u


def policy(name="p", disabled=False, mfa_required=True, factors=None, ptype="user_portal"):
    return {"id": name, "name": name, "type": ptype, "disabled": disabled,
            "effect": {"action": "allow", "obligations": {"mfa": {"required": mfa_required},
                                                          "mfaFactors": factors or ["TOTP"]}}}


@pytest.mark.parametrize("key", ALL_KEYS)
@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(key, name):
    value, status = run(key, NO_EVIDENCE[name])
    assert value is None and status == "error"


@pytest.mark.parametrize("key", USER_KEYS)
def test_partial_user_read_is_unevaluated(key):
    body = {"totalCount": 3, "results": [user(_id="a"), user(_id="b")]}
    assert run(key, body) == (None, "error")


@pytest.mark.parametrize("key", USER_KEYS)
def test_user_body_without_total_or_users_is_unevaluated(key):
    assert run(key, {"results": [user()]}) == (None, "error")
    assert run(key, {"totalCount": 0, "results": []}) == (None, "error")


@pytest.mark.parametrize("key", USER_KEYS)
def test_complete_user_read_evaluates(key):
    body = {"totalCount": 2, "results": [user(_id="a", totp_enabled=True,
                                              mfa={"configured": True, "exclusion": False}), user(_id="b")]}
    value, status = run(key, body)
    assert value is not None and status == "success"


def test_mfa_exclusion_and_not_enrolled_strings_are_not_mfa():
    excluded = user(mfa={"configured": False, "exclusion": True, "exclusionUntil": "2027-01-01"})
    body = {"totalCount": 1, "results": [excluded]}
    assert run("isMFAEnabled", body) == (False, "success")
    assert run("mfaDeviceEnrollmentPercentage", body) == (0.0, "success")


def test_mfa_configured_counts():
    body = {"totalCount": 2, "results": [user(_id="a", mfa={"configured": True, "exclusion": False}), user(_id="b")]}
    assert run("isMFAEnabled", body) == (True, "success")
    assert run("mfaDeviceEnrollmentPercentage", body)[0] == 50.0


@pytest.mark.parametrize("key", ["isSmsAuthenticationDisabled", "passwordOnlyAuthPolicyRulesCount",
                                 "relyingPartyTrustsWithoutAccessControlPolicyCount", "authTypesAllowed"])
def test_passing_answer_from_no_enabled_policy_is_unevaluated(key):
    assert run(key, []) == (None, "error")
    assert run(key, [policy(disabled=True)]) == (None, "error")


def test_sms_discriminates_on_real_policies():
    assert run("isSmsAuthenticationDisabled", [policy(factors=["TOTP", "WEBAUTHN"])]) == (True, "success")
    assert run("isSmsAuthenticationDisabled", [policy(factors=["TOTP", "SMS"])]) == (False, "success")


def test_password_only_rule_is_counted():
    assert run("passwordOnlyAuthPolicyRulesCount", [policy(mfa_required=False)]) == (1, "success")
    assert run("passwordOnlyAuthPolicyRulesCount", [policy(mfa_required=True)]) == (0, "success")


@pytest.mark.parametrize("key", ["isMFAEnforced", "areConditionalAccessPoliciesConfigured"])
def test_policy_results_envelope_and_bare_list_agree(key):
    assert run(key, [policy()]) == run(key, {"results": [policy()], "totalCount": 1})
    assert run(key, [policy()])[0] is True


def test_sso_apps():
    apps = [{"id": "1", "name": "a", "sso": {"type": "saml", "active": True}}]
    assert run("isSSOEnabled", apps) == (True, "success")
    assert run("isSSOEnabled", []) == (False, "success")
