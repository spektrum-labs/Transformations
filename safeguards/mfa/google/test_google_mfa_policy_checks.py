"""Google - MFA: isAuditLoggingEnabled (checkAuditLogs), confirmPasswordPolicyEnforced and
authTypesAllowed (getPolicies).

Real payloads (one customer tenant, 2026-09-25, redacted to structure in fixtures/):
  * the Admin audit feed checkAuditLogs returns (Reports API, applicationName admin);
  * a Cloud Identity policy page (gmail settings, SYSTEM defaults, booleans as strings,
    nextPageToken present). No live security.* policy page exists yet: getPolicies was never
    called for these keys. The security bodies below follow the documented setting schema
    (docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings) inside the real
    envelope.
Each check: real, flipped, empty, None, error envelope."""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
FIX = HERE / "fixtures"


def load(name):
    spec = importlib.util.spec_from_file_location("google_mfa_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = load("isauditloggingenabled")
PASSWORD = load("confirmpasswordpolicyenforced")
FACTORS = load("authtypesallowed")

ERROR = {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"}
GOOGLE_ERROR = {"error": {"code": 403, "status": "PERMISSION_DENIED",
                          "message": "Request had insufficient authentication scopes."}}


def verdict(module, body, key):
    out = module.transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def fixture(name):
    return json.loads((FIX / name).read_text())


def rebased_audit():
    """The real feed with its times shifted so the newest event is one day old (the rule is
    relative to now; the capture date is not)."""
    body = fixture("google_admin_audit_real_2026-09-25.json")
    times = [datetime.fromisoformat(i["id"]["time"].replace("Z", "+00:00")) for i in body["items"]]
    shift = datetime.now(timezone.utc) - timedelta(days=1) - max(times)
    for item, when in zip(body["items"], times):
        item["id"]["time"] = (when + shift).isoformat()
    return body


def policy(kind, value, org="orgUnits/root", ptype="ADMIN"):
    return {"name": "policies/x", "customer": "customers/x",
            "policyQuery": {"orgUnit": org, "sortOrder": "1"},
            "setting": {"type": "settings/" + kind, "value": value}, "type": ptype}


def security_page():
    body = fixture("google_policies_gmail_real_2026-09-25.json")
    body.pop("nextPageToken")
    body["policies"] = body["policies"] + [
        policy("security.password", {"allowedStrength": "STRONG", "minimumLength": "12", "maximumLength": "100",
                                     "enforceRequirementsAtLogin": "True", "allowReuse": "False",
                                     "expirationDuration": "0s"}, ptype="SYSTEM"),
        policy("security.password", {"allowedStrength": "STRONG", "minimumLength": 14,
                                     "enforceRequirementsAtLogin": True}, org="orgUnits/servers"),
        policy("security.two_step_verification_enrollment", {"allowEnrollment": "True"}),
        policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "PASSKEY_ONLY"}),
        policy("security.two_step_verification_enforcement_factor", {"allowedSignInFactorSet": "NO_TELEPHONY"},
               org="orgUnits/field"),
    ]
    return body


def find(body, kind, org):
    for p in body["policies"]:
        if p["setting"]["type"] == "settings/" + kind and p["policyQuery"]["orgUnit"] == org:
            return p
    raise KeyError(kind)


# ---- isAuditLoggingEnabled -------------------------------------------------------------------

def test_audit_real_feed_passes():
    assert verdict(AUDIT, rebased_audit(), "isAuditLoggingEnabled") == (True, "success")
    assert verdict(AUDIT, json.dumps(rebased_audit()), "isAuditLoggingEnabled") == (True, "success")
    assert verdict(AUDIT, {"apiResponse": rebased_audit()}, "isAuditLoggingEnabled") == (True, "success")


def test_audit_flipped_stale_or_empty_fails():
    stale = rebased_audit()
    for item in stale["items"]:
        item["id"]["time"] = "2025-01-01T00:00:00Z"
    assert verdict(AUDIT, stale, "isAuditLoggingEnabled") == (False, "success")
    empty_feed = {"kind": "admin#reports#activities", "items": []}
    assert verdict(AUDIT, empty_feed, "isAuditLoggingEnabled") == (False, "success")


def test_audit_other_application_not_measured():
    body = rebased_audit()
    for item in body["items"]:
        item["id"]["applicationName"] = "gmail"
    assert verdict(AUDIT, body, "isAuditLoggingEnabled") == (False, "error")


def test_audit_fail_closed_inputs():
    for body in ({}, None, "", "{}", ERROR, GOOGLE_ERROR, [], {"items": []}):
        assert verdict(AUDIT, body, "isAuditLoggingEnabled") == (False, "error"), body


# ---- confirmPasswordPolicyEnforced ----------------------------------------------------------

def test_password_real_gmail_page_is_not_measured():
    real = fixture("google_policies_gmail_real_2026-09-25.json")
    assert verdict(PASSWORD, real, "confirmPasswordPolicyEnforced") == (False, "error")  # truncated
    real.pop("nextPageToken")
    assert verdict(PASSWORD, real, "confirmPasswordPolicyEnforced") == (False, "error")  # no password policy


def test_password_strong_everywhere_passes():
    assert verdict(PASSWORD, security_page(), "confirmPasswordPolicyEnforced") == (True, "success")
    assert verdict(PASSWORD, json.dumps(security_page()), "confirmPasswordPolicyEnforced") == (True, "success")


def test_password_one_weak_org_unit_fails():
    for field, bad in (("allowedStrength", "WEAK"), ("minimumLength", "6"),
                       ("enforceRequirementsAtLogin", "False")):
        body = security_page()
        find(body, "security.password", "orgUnits/servers")["setting"]["value"][field] = bad
        assert verdict(PASSWORD, body, "confirmPasswordPolicyEnforced") == (False, "success"), field


def test_password_fail_closed_inputs():
    for body in ({}, None, "", "{}", ERROR, GOOGLE_ERROR, {"policies": []}, {"policies": "x"}):
        assert verdict(PASSWORD, body, "confirmPasswordPolicyEnforced") == (False, "error"), body


# ---- authTypesAllowed -----------------------------------------------------------------------

def test_factors_real_gmail_page_is_not_measured():
    real = fixture("google_policies_gmail_real_2026-09-25.json")
    assert verdict(FACTORS, real, "authTypesAllowed") == (False, "error")
    real.pop("nextPageToken")
    assert verdict(FACTORS, real, "authTypesAllowed") == (False, "error")


def test_factors_strong_everywhere_passes():
    assert verdict(FACTORS, security_page(), "authTypesAllowed") == (True, "success")


def test_factors_sms_allowed_or_enrollment_off_fails():
    body = security_page()
    find(body, "security.two_step_verification_enforcement_factor", "orgUnits/field")["setting"]["value"][
        "allowedSignInFactorSet"] = "ALL"
    assert verdict(FACTORS, body, "authTypesAllowed") == (False, "success")
    body = security_page()
    find(body, "security.two_step_verification_enrollment", "orgUnits/root")["setting"]["value"][
        "allowEnrollment"] = "False"
    assert verdict(FACTORS, body, "authTypesAllowed") == (False, "success")
    body = security_page()
    find(body, "security.two_step_verification_enforcement_factor", "orgUnits/root")["setting"]["value"][
        "allowedSignInFactorSet"] = "SOMETHING_NEW"
    assert verdict(FACTORS, body, "authTypesAllowed") == (False, "success")


def test_factors_fail_closed_inputs():
    for body in ({}, None, "", "{}", ERROR, GOOGLE_ERROR, {"policies": []}):
        assert verdict(FACTORS, body, "authTypesAllowed") == (False, "error"), body
    truncated = copy.deepcopy(security_page())
    truncated["nextPageToken"] = "more"
    assert verdict(FACTORS, truncated, "authTypesAllowed") == (False, "error")
