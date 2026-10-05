"""isMFAEnforcedForUsers (874a78ff/ismfaenforcedforusers.py): weak factors do not count as MFA.

Definitions that feed this file only the authentication methods policy reach its fallback branch. Before
5 Oct 2026 that branch read True when ANY method was enabled, so a tenant whose only enabled method was Email
OTP passed. J.J.'s rule (3 Oct 2026): email one-time passcodes (guest-only Email OTP included), SMS and voice
are weak factors. SYNTHETIC fixtures in the Graph shapes. Each case runs as plain Python and in the
Token-Service sandbox replica, typed and with every leaf stringified (the stored-response form).
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

TAG = "ms365mfaweak"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]
KEY = "isMFAEnforcedForUsers"
IDS = ["Email", "Fido2", "MicrosoftAuthenticator", "QRCodePin", "Sms", "SoftwareOath",
       "TemporaryAccessPass", "VerifiableCredentials", "Voice", "X509Certificate"]
EXTERNAL = {
    "@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration",
    "id": "00000000-0000-0000-0000-0000000000aa",
    "state": "enabled",
    "displayName": "External MFA provider",
}


def load(mode):
    path = HERE / "ismfaenforcedforusers.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_ismfaenforcedforusers", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def stringify(x):
    if isinstance(x, dict):
        return {k: stringify(v) for k, v in x.items()}
    if isinstance(x, list):
        return [stringify(v) for v in x]
    return "None" if x is None else str(x)


def methods_policy(enabled=(), extra=(), email_external="default", email_targets="members"):
    configs = []
    for i in IDS:
        c = {"id": i, "state": "enabled" if i in enabled else "disabled"}
        if i == "Email":
            c["allowExternalIdToUseEmailOtp"] = email_external
            if email_targets == "guests_only":
                c["includeTargets"] = []
            elif email_targets == "all_users":
                c["includeTargets"] = [{"targetType": "group", "id": "all_users", "isRegistrationRequired": False}]
        configs.append(c)
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
        "id": "authenticationMethodsPolicy",
        "policyMigrationState": "migrationInProgress",
        "authenticationMethodConfigurations": configs + [copy.deepcopy(e) for e in extra],
    }


def run(body, mode, typed=True):
    out = load(mode)(copy.deepcopy(body) if typed else stringify(body))
    return out["transformedResponse"].get(KEY), out["additionalInfo"]["dataCollection"]["status"], out


CASES = [
    # (name, enabled methods, extra configs, expected value, expected dataCollection status)
    ("email_only", ["Email"], [], False, "success"),
    ("sms_voice_email", ["Sms", "Voice", "Email"], [], False, "success"),
    # J.J. 5 Oct: no method that targets members means the methods policy is not evidence -> not evaluated.
    ("nothing_enabled", [], [], None, "error"),
    ("authenticator", ["MicrosoftAuthenticator", "Email"], [], True, "success"),
    ("fido2", ["Fido2"], [], True, "success"),
    ("software_oath", ["SoftwareOath", "Sms"], [], True, "success"),
    ("external_only", [], [EXTERNAL], None, "error"),
    ("external_and_email", ["Email"], [EXTERNAL], None, "error"),
    ("external_and_authenticator", ["MicrosoftAuthenticator"], [EXTERNAL], True, "success"),
    ("qr_and_certificate_only", ["QRCodePin", "X509Certificate", "VerifiableCredentials"], [], False, "success"),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("typed", [True, False])
@pytest.mark.parametrize("name,enabled,extra,expected,status", CASES, ids=[c[0] for c in CASES])
def test_methods_policy(mode, typed, name, enabled, extra, expected, status):
    value, dc, out = run(methods_policy(enabled, extra), mode, typed)
    assert value is expected
    assert dc == status


@pytest.mark.parametrize("mode", MODES)
def test_guest_email_otp_does_not_count(mode):
    value, dc, out = run(methods_policy(["Email"], email_external="enabled"), mode)
    assert value is False and dc == "success"
    assert out["transformedResponse"]["weakMethodsEnabled"] == ["Email"]
    assert "weak" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"]).lower()


@pytest.mark.parametrize("mode", MODES)
def test_strong_methods_listed_weak_methods_reported(mode):
    value, dc, out = run(methods_policy(["MicrosoftAuthenticator", "Sms", "Email"]), mode)
    assert value is True
    assert [m["id"] for m in out["transformedResponse"]["mfaTypes"]] == ["MicrosoftAuthenticator"]
    assert out["transformedResponse"]["weakMethodsEnabled"] == ["Email", "Sms"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [{}, {"value": []}, {"authenticationMethodConfigurations": None}],
                         ids=["empty", "empty_secure_score", "null_configurations"])
def test_nothing_read_is_not_evaluated(mode, body):
    value, dc, out = run(body, mode)
    assert value is None and dc == "error"


@pytest.mark.parametrize("mode", MODES)
def test_secure_score_branch_unchanged(mode):
    body = {"value": [{"controlScores": [{"controlName": "MFARegistrationV2", "scoreInPercentage": 100.0,
                                          "count": 10, "total": 10}]}]}
    value, dc, out = run(body, mode)
    assert value is True and dc == "success"
    body["value"][0]["controlScores"][0].update(scoreInPercentage=80.0, count=8)
    value, dc, out = run(body, mode)
    assert value is False


@pytest.mark.parametrize("mode", MODES)
def test_vendor_error_is_not_a_pass(mode):
    value, dc, out = run({"PSError": "HTTP 403 Forbidden"}, mode)
    assert value is False and dc == "error"


GUEST_CASES = [
    # (name, enabled, email_targets, expected value, expected dataCollection status)
    ("guest_only_email", ["Email"], "guests_only", None, "error"),
    ("all_users_email", ["Email"], "all_users", False, "success"),
    ("guest_only_email_and_sms", ["Email", "Sms"], "guests_only", False, "success"),
    ("guest_only_email_and_authenticator", ["Email", "MicrosoftAuthenticator"], "guests_only", True, "success"),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name,enabled,targets,expected,status", GUEST_CASES, ids=[c[0] for c in GUEST_CASES])
def test_guest_only_email(mode, name, enabled, targets, expected, status):
    value, dc, out = run(methods_policy(enabled, email_targets=targets), mode, True)
    assert value is expected
    assert dc == status
    if expected is None:
        assert out["additionalInfo"]["dataCollection"]["errors"]
