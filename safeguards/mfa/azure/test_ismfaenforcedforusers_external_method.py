"""isMFAEnforcedForUsers (safeguards/mfa/azure/ismfaenforcedforusers.py): an external authentication method.

Azure AD (d9b6f27a, refs/heads/main) and Azure AD One-Click (cde89168, pinned ea2d2a3f) run this file on the
merged workflow body {"authMethodsPolicy": ..., "conditionalAccessPolicies": ...}.

Finding (false-fail check, 3 Oct 2026, REPORT.md section 6): estate A enforces MFA through Cisco Duo as
an Entra external authentication method and FAILED with "No MFA authentication methods enabled at the tenant
level". J.J.'s rule (3 Oct 2026): an external method alone cannot be graded from Entra and reads NOT EVALUATED,
never FAIL. SYNTHETIC fixtures in the Graph shapes; the Duo configuration mirrors the one stored for estate A
(client id and app id replaced). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "azmfaext"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # without RestrictedPython the "sandbox" leg runs as plain exec (CI installs requirements-test.txt,
    # which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]
KEY = "isMFAEnforcedForUsers"


def load(mode):
    path = HERE / "ismfaenforcedforusers.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_ismfaenforcedforusers", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(body, mode):
    out = load(mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(KEY), out["additionalInfo"]["dataCollection"]["status"], out


DUO = {
    "@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration",
    "id": "bfa47a53-8f7d-4058-9e4b-db9247a8d1bf",
    "state": "enabled",
    "displayName": "Cisco Duo",
    "appId": "00000000-0000-0000-0000-000000000000",
    "excludeTargets": [],
    "openIdConnectSetting": {"clientId": "synthetic",
                             "discoveryUrl": "https://us.azureauth.duosecurity.com/.well-known/openid-configuration"},
    "includeTargets": [{"targetType": "group", "id": "all_users", "isRegistrationRequired": False}],
}
IDS = ["Email", "Fido2", "MicrosoftAuthenticator", "QRCodePin", "Sms", "SoftwareOath",
       "TemporaryAccessPass", "VerifiableCredentials", "Voice", "X509Certificate"]


def methods_policy(enabled=(), extra=()):
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/$entity",
        "id": "authenticationMethodsPolicy",
        "policyMigrationState": "migrationComplete",
        "authenticationMethodConfigurations": [{"id": i, "state": "enabled" if i in enabled else "disabled"}
                                               for i in IDS] + [copy.deepcopy(e) for e in extra],
    }


def ca_policy(name, users=("All",), groups=(), grant=("mfa",), state="enabled"):
    return {"displayName": name, "state": state,
            "conditions": {"users": {"includeUsers": list(users), "includeGroups": list(groups)},
                           "applications": {"includeApplications": ["All"]}},
            "grantControls": {"operator": "OR", "builtInControls": list(grant)}}


def body(enabled=(), extra=(), policies=None):
    if policies is None:
        policies = [ca_policy("Require Duo Mfa"),
                    ca_policy("Microsoft-managed: Multifactor authentication and reauthentication for risky sign-ins")]
    return {"authMethodsPolicy": methods_policy(enabled, extra),
            "conditionalAccessPolicies": {"value": policies}}


@pytest.mark.parametrize("mode", MODES)
def test_external_method_only_is_not_evaluated(mode):
    # Estate A: Duo is the only enabled method, two CA policies require MFA for all users.
    value, status, out = run(body(extra=[DUO]), mode)
    assert value is None and status == "error"
    reason = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
    assert "external authentication method (e.g. Duo); Entra cannot grade it" in reason
    assert "Cisco Duo" in reason
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []
    assert out["transformedResponse"]["externalMethods"] == ["Cisco Duo"]
    assert "Require Duo Mfa" in " ".join(out["additionalInfo"]["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("mode", MODES)
def test_external_method_with_weak_or_no_ca_policy_is_never_fail(mode):
    # No Microsoft MFA method is enabled but an external method exists (with SMS/email beside it, or with no
    # CA policy requiring MFA): still not evaluated, never FAIL.
    for b in (body(enabled={"Sms", "Email"}, extra=[DUO]), body(extra=[DUO], policies=[])):
        value, status, _ = run(b, mode)
        assert (value, status) == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_no_methods_and_no_external_method_fails_as_today(mode):
    for b in (body(), body(enabled={"Email"}), body(policies=[])):
        value, status, out = run(b, mode)
        assert (value, status) == (False, "success")
        assert "No MFA authentication methods enabled at the tenant level" in out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("mode", MODES)
def test_disabled_external_method_does_not_rescue_a_fail(mode):
    off = dict(DUO, state="disabled")
    assert run(body(extra=[off]), mode)[:2] == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_strong_methods_enabled_unchanged(mode):
    # Methods plus a CA policy for all users: PASS, as before.
    value, status, out = run(body(enabled={"MicrosoftAuthenticator", "Fido2"}), mode)
    assert (value, status) == (True, "success")
    assert out["transformedResponse"]["enabledMethods"] == ["Fido2", "MicrosoftAuthenticator"]
    # Group-targeted policy still counts; strong methods plus Duo still pass on the Microsoft evidence.
    assert run(body(enabled={"Fido2"}, policies=[ca_policy("MFA", users=(), groups=("g1",))]), mode)[:2] == (True, "success")
    assert run(body(enabled={"MicrosoftAuthenticator"}, extra=[DUO]), mode)[:2] == (True, "success")
    # Strong methods but no CA policy requiring MFA (or only a disabled / non-MFA one): FAIL, as before.
    for policies in ([], [ca_policy("off", state="disabled")], [ca_policy("block", grant=("block",))]):
        value, status, out = run(body(enabled={"MicrosoftAuthenticator"}, policies=policies), mode)
        assert (value, status) == (False, "success")
        assert out["additionalInfo"]["evaluation"]["failReasons"] == [
            "No enabled conditional access policies requiring MFA for all users"]
    # Strong methods plus Duo but no CA policy: the Microsoft evidence is gradeable, FAIL as before.
    assert run(body(enabled={"MicrosoftAuthenticator"}, extra=[DUO], policies=[]), mode)[:2] == (False, "success")


NO_EVIDENCE = [None, {}, [], "", "{}",
               {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
               {"authMethodsPolicy": {"error": {"code": "Forbidden"}}, "conditionalAccessPolicies": {"value": []}},
               {"authMethodsPolicy": {"authenticationMethodConfigurations": []}, "conditionalAccessPolicies": {"value": []}},
               {"authMethodsPolicy": methods_policy({"Fido2"})},
               {"authMethodsPolicy": methods_policy({"Fido2"}), "conditionalAccessPolicies": {"error": {"code": "403"}}},
               {"data": {}, "validation": {"status": "failed", "errors": ["x"], "warnings": []}}]


@pytest.mark.parametrize("mode", MODES)
def test_missing_data_never_passes(mode):
    for b in NO_EVIDENCE:
        value, status, _ = run(b, mode)
        assert value is not True, b
        assert (value, status) == (None, "error"), b


@pytest.mark.parametrize("mode", MODES)
def test_token_service_envelope_and_string_body(mode):
    import json
    wrapped = {"data": body(extra=[DUO]), "validation": {"status": "skipped", "errors": [], "warnings": []}}
    assert run(wrapped, mode)[:2] == (None, "error")
    assert run(json.dumps(body(enabled={"Fido2"})), mode)[:2] == (True, "success")
