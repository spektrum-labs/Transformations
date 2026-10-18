"""Google - MFA getPolicies: a truncated policy list (nextPageToken still present) can settle a failure, never a pass.

confirmPasswordPolicyEnforced and authTypesAllowed need EVERY policy to meet the standard. A weak password policy, a
factor policy that still allows SMS or voice codes, or an enrollment policy that forbids 2-Step Verification, once
read, cannot be undone by an unread page. So a truncated list with such a policy is a measured False, with the reason
saying the list was incomplete. A truncated list with nothing wrong in the pages read stays Not evaluated (an unread
page could hold the weak policy), and so does a truncated list with no policy of the kind at all. A True needs the
whole list.

All bodies here are synthetic.
"""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("google_mfa_trunc_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PASSWORD = load("confirmpasswordpolicyenforced")
FACTORS = load("authtypesallowed")


def policy(kind, value, org):
    return {"name": "policies/example", "customer": "customers/example",
            "policyQuery": {"orgUnit": org, "sortOrder": "1"},
            "setting": {"type": "settings/" + kind, "value": value}, "type": "ADMIN"}


STRONG = {"allowedStrength": "STRONG", "minimumLength": "12", "enforceRequirementsAtLogin": "True"}
WEAK = {"allowedStrength": "WEAK", "minimumLength": "8", "enforceRequirementsAtLogin": "False"}
NOISE = policy("rule.dlp", {"name": "example"}, "orgUnits/example-noise")


def page(policies, token="more"):
    body = {"policies": policies}
    if token:
        body["nextPageToken"] = token
    return body


def verdict(module, body, key):
    out = module.transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"], out


def test_password_weak_policy_in_a_truncated_list_is_a_measured_false():
    body = page([NOISE, policy("security.password", STRONG, "orgUnits/a"), policy("security.password", WEAK, "orgUnits/b")])
    value, status, out = verdict(PASSWORD, body, "confirmPasswordPolicyEnforced")
    assert (value, status) == (False, "success")
    assert "truncated" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


def test_password_truncated_list_with_nothing_wrong_is_not_evaluated():
    body = page([NOISE, policy("security.password", STRONG, "orgUnits/a"), policy("security.password", STRONG, "orgUnits/b")])
    value, status, out = verdict(PASSWORD, body, "confirmPasswordPolicyEnforced")
    assert (value, status) == (False, "error")
    assert "truncated" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_password_truncated_list_with_no_password_policy_is_not_evaluated():
    assert verdict(PASSWORD, page([NOISE]), "confirmPasswordPolicyEnforced")[:2] == (False, "error")
    assert verdict(PASSWORD, page([]), "confirmPasswordPolicyEnforced")[:2] == (False, "error")


def test_password_complete_list_is_unchanged():
    strong = page([policy("security.password", STRONG, "orgUnits/a")], token=None)
    weak = page([policy("security.password", STRONG, "orgUnits/a"), policy("security.password", WEAK, "orgUnits/b")], token=None)
    assert verdict(PASSWORD, strong, "confirmPasswordPolicyEnforced")[:2] == (True, "success")
    value, status, out = verdict(PASSWORD, weak, "confirmPasswordPolicyEnforced")
    assert (value, status) == (False, "success")
    assert "truncated" not in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert verdict(PASSWORD, page([NOISE], token=None), "confirmPasswordPolicyEnforced")[:2] == (False, "error")


def test_password_a_truncated_list_never_passes():
    for token in ("more", "x", "1"):
        body = page([policy("security.password", STRONG, "orgUnits/a")], token=token)
        assert verdict(PASSWORD, json.dumps(body), "confirmPasswordPolicyEnforced")[:2] == (False, "error")


def test_factors_sms_allowed_in_a_truncated_list_is_a_measured_false():
    body = page([NOISE,
                 policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "orgUnits/a"),
                 policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "ALL"}, "orgUnits/b")])
    value, status, out = verdict(FACTORS, body, "authTypesAllowed")
    assert (value, status) == (False, "success")
    assert "truncated" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_factors_enrollment_forbidden_in_a_truncated_list_is_a_measured_false():
    body = page([policy("security.two_step_verification_enrollment", {"allowEnrollment": "False"}, "orgUnits/a")])
    assert verdict(FACTORS, body, "authTypesAllowed")[:2] == (False, "success")


def test_factors_truncated_list_with_nothing_wrong_is_not_evaluated():
    body = page([policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "orgUnits/a"),
                 policy("security.two_step_verification_enrollment", {"allowEnrollment": "True"}, "orgUnits/a")])
    value, status, out = verdict(FACTORS, body, "authTypesAllowed")
    assert (value, status) == (False, "error")
    assert "truncated" in out["additionalInfo"]["dataCollection"]["errors"][0]
    assert verdict(FACTORS, page([NOISE]), "authTypesAllowed")[:2] == (False, "error")
    assert verdict(FACTORS, page([]), "authTypesAllowed")[:2] == (False, "error")


def test_factors_complete_list_is_unchanged():
    ok = page([policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "NO_TELEPHONY"}, "orgUnits/a")], token=None)
    bad = page([policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "ALL"}, "orgUnits/a")], token=None)
    assert verdict(FACTORS, ok, "authTypesAllowed")[:2] == (True, "success")
    value, status, out = verdict(FACTORS, bad, "authTypesAllowed")
    assert (value, status) == (False, "success")
    assert "truncated" not in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert verdict(FACTORS, page([NOISE], token=None), "authTypesAllowed")[:2] == (False, "error")


def test_error_and_non_list_bodies_stay_not_evaluated_whatever_the_token():
    for module, key in ((PASSWORD, "confirmPasswordPolicyEnforced"), (FACTORS, "authTypesAllowed")):
        for body in ({}, None, "", "{}", {"error": {"code": 403, "message": "denied"}}, {"nextPageToken": "x"}, {"policies": "x"}):
            assert verdict(module, body, key)[:2] == (False, "error"), (key, body)


def test_a_weak_system_default_alone_does_not_settle_a_truncated_list():
    """Google's SYSTEM default (weak password, factor set ALL) is overridden by an administrator policy at the same
    org unit, so reading it in a truncated list says nothing about the tenant's effective setting."""
    system_weak = dict(policy("security.password", WEAK, "orgUnits/root"), type="SYSTEM")
    body = page([NOISE, system_weak, policy("security.password", STRONG, "orgUnits/root")])
    value, status, _ = verdict(PASSWORD, body, "confirmPasswordPolicyEnforced")
    assert (value, status) == (False, "error")
    system_factor = dict(policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "ALL"},
                                "orgUnits/root"), type="SYSTEM")
    body = page([system_factor, policy("security.two_step_verification_enforcement_factor",
                                       {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "orgUnits/root")])
    value, status, _ = verdict(FACTORS, body, "authTypesAllowed")
    assert (value, status) == (False, "error")
