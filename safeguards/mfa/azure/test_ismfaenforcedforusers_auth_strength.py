"""mfa/azure/ismfaenforcedforusers.py: authentication strengths and the full set of MFA methods (Entra MFA review
write-up, defect 1).

1. An enabled All-users policy that requires an authentication strength made only of MFA combinations counts as
   MFA, the same as the built-in "mfa" grant. Before this change such a tenant read Failed ("No enabled conditional
   access policies requiring MFA for all users"). A strength that allows a single-factor sign-in (password alone,
   SMS sign-in, single-factor certificate, ...) does not count, as before. A strength this check cannot grade (no
   allowedCombinations and not a built-in strength, or a combination it does not know) sets the policy aside, so
   the check reads Not evaluated, never Failed.
2. Certificate-based authentication in multi-factor mode and hardware OATH tokens are MFA methods, as software
   OATH already was. Before this change a tenant whose only member methods were those read Failed ("No MFA
   authentication methods enabled at the tenant level"). Single-factor certificate authentication still does not
   count.

Synthetic estate only (public repo). Every case also runs under the Token-Service sandbox replica.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
KEY = "isMFAEnforcedForUsers"
G1 = "c0000000-0000-0000-0000-000000000001"
U = ["a0000000-0000-0000-0000-00000000000%d" % i for i in range(1, 5)]

MULTIFACTOR = "00000000-0000-0000-0000-000000000002"
PASSWORDLESS = "00000000-0000-0000-0000-000000000003"
PHISHING_RESISTANT = "00000000-0000-0000-0000-000000000004"
CUSTOM = "d0000000-0000-0000-0000-000000000001"

MULTIFACTOR_COMBINATIONS = [
    "windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "deviceBasedPush",
    "temporaryAccessPassOneTime", "temporaryAccessPassMultiUse", "password,microsoftAuthenticatorPush",
    "password,softwareOath", "password,hardwareOath", "password,sms", "password,voice", "federatedMultiFactor",
    "microsoftAuthenticatorPush,federatedSingleFactor", "softwareOath,federatedSingleFactor",
    "hardwareOath,federatedSingleFactor", "sms,federatedSingleFactor", "voice,federatedSingleFactor",
]


def load_plain():
    spec = importlib.util.spec_from_file_location("ismfa_strength", HERE / "ismfaenforcedforusers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandbox():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_strength", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / "ismfaenforcedforusers.py").read_text(), "<transformation>")["transform"]


def _runners():
    runners = [pytest.param(load_plain, id="plain")]
    try:
        import RestrictedPython  # noqa: F401
        runners.append(pytest.param(load_sandbox, id="sandbox"))
    except ImportError:  # CI installs RestrictedPython from requirements-test.txt
        pass
    return runners


@pytest.fixture(params=_runners(), scope="module")
def tx(request):
    return request.param()


def methods(*configs):
    configs = configs or ({"id": "MicrosoftAuthenticator", "state": "enabled"},)
    return {"authenticationMethodConfigurations": list(configs)}


def strength(sid=MULTIFACTOR, combinations=None, name="Multifactor authentication", **extra):
    s = {"id": sid, "displayName": name}
    if combinations is not None:
        s["allowedCombinations"] = list(combinations)
    s.update(extra)
    return s


def policy(name="Require MFA for all users", grant=None, include_users=("All",), include_groups=(), conditions=None,
           **users):
    u = {"includeUsers": list(include_users), "includeGroups": list(include_groups), "excludeUsers": [],
         "excludeGroups": [], "includeRoles": [], "excludeRoles": []}
    u.update(users)
    c = {"users": u, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]}
    c.update(conditions or {})
    return {"displayName": name, "state": "enabled", "conditions": c,
            "grantControls": grant if grant is not None else {"operator": "OR", "builtInControls": ["mfa"]}}


def strength_grant(s, operator="OR", built_in=()):
    return {"operator": operator, "builtInControls": list(built_in), "authenticationStrength": s}


def body(*policies, auth=None):
    return {"authMethodsPolicy": auth or methods(), "conditionalAccessPolicies": {"value": list(policies)}}


def run(fn, b):
    out = fn(copy.deepcopy(b))
    return out["transformedResponse"][KEY], out


def errors(out):
    return " ".join(out["additionalInfo"]["dataCollection"]["errors"])


# --- 1. authentication strength on an All-users policy ---------------------------------------------------------------

def test_builtin_multifactor_strength_with_its_combinations_passes(tx):
    value, out = run(tx, body(policy(grant=strength_grant(strength(combinations=MULTIFACTOR_COMBINATIONS)))))
    assert value is True
    assert out["transformedResponse"]["policiesEnforcingMFAForUsers"] == ["Require MFA for all users"]
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("sid", [MULTIFACTOR, PASSWORDLESS, PHISHING_RESISTANT])
def test_builtin_strength_named_only_by_id_passes(tx, sid):
    value, _ = run(tx, body(policy(grant=strength_grant(strength(sid=sid)))))
    assert value is True


def test_phishing_resistant_strength_passes(tx):
    s = strength(sid=PHISHING_RESISTANT, combinations=["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"])
    assert run(tx, body(policy(grant=strength_grant(s, operator="AND"))))[0] is True


def test_custom_strength_made_only_of_mfa_combinations_passes(tx):
    s = strength(sid=CUSTOM, name="Custom MFA", combinations=["password, softwareOath", "FIDO2", "password,hardwareOath"])
    assert run(tx, body(policy(grant=strength_grant(s))))[0] is True


def test_custom_strength_with_requirements_satisfied_mfa_and_no_combinations_passes(tx):
    s = strength(sid=CUSTOM, name="Custom MFA", requirementsSatisfied="mfa")
    assert run(tx, body(policy(grant=strength_grant(s))))[0] is True


@pytest.mark.parametrize("single", ["password", "sms", "voice", "email", "x509CertificateSingleFactor",
                                    "federatedSingleFactor", "qrCodePin"])
def test_strength_allowing_a_single_factor_sign_in_does_not_count(tx, single):
    s = strength(sid=CUSTOM, name="Custom weak", combinations=["fido2", single])
    value, out = run(tx, body(policy(grant=strength_grant(s))))
    assert value is False  # unchanged: a single-factor sign-in satisfies this policy
    assert "No enabled conditional access policies requiring MFA for all users" in " ".join(
        out["additionalInfo"]["evaluation"]["failReasons"])


def test_strength_whose_requirements_are_none_does_not_count(tx):
    s = strength(sid=CUSTOM, name="Custom", requirementsSatisfied="none")
    assert run(tx, body(policy(grant=strength_grant(s))))[0] is False


@pytest.mark.parametrize("s", [
    strength(sid=CUSTOM, name="Custom, combinations not returned"),
    strength(sid=CUSTOM, name="Custom", combinations=["fido2", "someFutureMethod"]),
    strength(sid=CUSTOM, name="Custom", combinations=[]),
    {"displayName": "no id"},
])
def test_strength_that_cannot_be_graded_is_not_evaluated(tx, s):
    value, out = run(tx, body(policy(grant=strength_grant(s))))
    assert value is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "authentication strength" in errors(out)


def test_strength_policy_excluding_a_group_is_set_aside_not_failed(tx):
    # Row 36B (c), decision 18 Oct 2026: one excluded group is break-glass, so two groups are needed to set it aside.
    p = policy(grant=strength_grant(strength(combinations=MULTIFACTOR_COMBINATIONS)),
               excludeGroups=[G1, "c0000000-0000-0000-0000-000000000002"])
    value, out = run(tx, body(p))
    assert value is None
    assert "excludes more than 1 group" in errors(out)


def test_strength_policy_excluding_one_break_glass_group_counts(tx):
    p = policy(grant=strength_grant(strength(combinations=MULTIFACTOR_COMBINATIONS)), excludeGroups=[G1])
    assert run(tx, body(p))[0] is True


def test_strength_policy_firing_only_on_risk_does_not_count(tx):
    p = policy(grant=strength_grant(strength(sid=MULTIFACTOR)), conditions={"signInRiskLevels": ["high"]})
    assert run(tx, body(p))[0] is False  # unchanged: risk-only policies never counted


def test_report_only_strength_policy_does_not_count(tx):
    p = policy(grant=strength_grant(strength(sid=MULTIFACTOR)))
    p["state"] = "enabledForReportingButNotEnforced"
    assert run(tx, body(p))[0] is False


def test_group_scoped_strength_policy_is_judged_from_membership(tx):
    p = policy(name="MFA for staff", include_users=(), include_groups=(G1,),
               grant=strength_grant(strength(sid=MULTIFACTOR), operator="AND"))
    b = body(p)
    b["workforceUsers"] = {"value": [{"id": i, "accountEnabled": True, "userType": "Member"} for i in U]}
    b["caPolicyGroups"] = {"groupIds": [{"id": G1}]}
    b["groupMembers"] = [{"value": [{"id": i} for i in U]}]
    value, out = run(tx, b)
    assert value is True
    assert out["transformedResponse"]["groupCoverage"]["coversAll"] is True


def test_group_scoped_strength_policy_without_membership_is_not_evaluated(tx):
    p = policy(name="MFA for staff", include_users=(), include_groups=(G1,),
               grant=strength_grant(strength(sid=MULTIFACTOR)))
    value, out = run(tx, body(p))
    assert value is None
    assert "targets groups" in errors(out)


def test_builtin_mfa_policy_output_is_unchanged_by_a_strength_policy_next_to_it(tx):
    plain = run(tx, body(policy()))[1]["transformedResponse"]
    both = run(tx, body(policy(), policy(name="Strength", grant=strength_grant(strength(sid=MULTIFACTOR)))))
    assert both[0] is True
    assert plain[KEY] is True


# --- 2. certificate-based authentication (multi-factor) and hardware OATH are MFA methods ----------------------------

CBA_MULTI = {"@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration", "id": "X509Certificate",
             "state": "enabled", "authenticationModeConfiguration": {
                 "x509CertificateAuthenticationDefaultMode": "x509CertificateMultiFactor", "rules": []}}
CBA_SINGLE = {"@odata.type": "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration", "id": "X509Certificate",
              "state": "enabled", "authenticationModeConfiguration": {
                  "x509CertificateAuthenticationDefaultMode": "x509CertificateSingleFactor", "rules": []}}
HARDWARE_OATH = {"@odata.type": "#microsoft.graph.hardwareOathAuthenticationMethodConfiguration", "id": "HardwareOath",
                 "state": "enabled"}
SMS = {"id": "Sms", "state": "enabled"}
DUO = {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "e0000000-0000-0000-0000-000000000001",
       "displayName": "Cisco Duo", "state": "enabled"}


@pytest.mark.parametrize("method", [CBA_MULTI, HARDWARE_OATH], ids=["cba-multifactor", "hardware-oath"])
def test_cba_multifactor_and_hardware_oath_are_mfa_methods(tx, method):
    value, out = run(tx, body(policy(), auth=methods(method, SMS)))
    assert value is True
    assert out["transformedResponse"]["mfaMethodsAvailable"] is True
    assert out["transformedResponse"]["enabledMethods"] == [method["id"]]


def test_single_factor_cba_is_still_not_an_mfa_method(tx):
    value, out = run(tx, body(policy(), auth=methods(CBA_SINGLE, SMS)))
    assert value is False  # unchanged
    assert "No MFA authentication methods enabled" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


def test_cba_with_no_mode_configuration_is_not_an_mfa_method(tx):
    bare = {"id": "X509Certificate", "state": "enabled"}
    assert run(tx, body(policy(), auth=methods(bare, SMS)))[0] is False  # unchanged


def test_disabled_hardware_oath_is_not_counted(tx):
    off = dict(HARDWARE_OATH, state="disabled")
    assert run(tx, body(policy(), auth=methods(off, SMS)))[0] is False  # unchanged


def test_new_method_next_to_an_external_one_never_reads_failed(tx):
    # Before: Duo with no Microsoft MFA method read Not evaluated. Adding CBA or hardware OATH may pass it when an
    # All-users MFA policy exists, and must not turn it into Failed when none does.
    assert run(tx, body(policy(), auth=methods(DUO, HARDWARE_OATH)))[0] is True
    value, out = run(tx, body(auth=methods(DUO, HARDWARE_OATH)))
    assert value is None
    assert "external authentication method" in errors(out)
    value, _ = run(tx, body(policy(include_users=(), include_groups=(G1,)), auth=methods(DUO, CBA_MULTI)))
    assert value is None


# --- review Medium: a strength next to another control under OR ------------------------------------------------------

def test_strength_or_compliant_device_is_not_enforcement(tx):
    # A compliant device alone satisfies this policy, so it does not require MFA (fail closed, as on develop).
    grant = strength_grant(strength(combinations=MULTIFACTOR_COMBINATIONS), operator="OR", built_in=("compliantDevice",))
    value, out = run(tx, body(policy(grant=grant)))
    assert value is not True
    assert out["transformedResponse"]["policiesEnforcingMFAForUsers"] == []


def test_strength_and_compliant_device_still_passes(tx):
    # Under AND the strength is always required, so the policy enforces MFA.
    grant = strength_grant(strength(combinations=MULTIFACTOR_COMBINATIONS), operator="AND", built_in=("compliantDevice",))
    value, _ = run(tx, body(policy(grant=grant)))
    assert value is True
