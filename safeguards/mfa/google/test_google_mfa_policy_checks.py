"""Google - MFA: isAuditLoggingEnabled (checkAuditLogs), confirmPasswordPolicyEnforced and
authTypesAllowed (getPolicies).

Real payloads (one customer tenant, 2026-09-25, redacted to structure in fixtures/):
  * the Admin audit feed checkAuditLogs returns (Reports API, applicationName admin);
  * a Cloud Identity policy page (gmail settings, SYSTEM defaults, booleans as strings,
    nextPageToken present). No live security.* policy page exists yet: getPolicies was never
    called for these keys. The security bodies below follow the documented setting schema
    (docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings) inside the real
    envelope.
Each check: real, flipped, and every read that proves nothing (error envelope, refusal, empty,
None, truncated, not JSON, no matching policy) is Not evaluated: every criterion key None and
dataCollection.status "error" with a reason, never False."""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

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


def test_audit_stale_feed_fails():
    stale = rebased_audit()
    for item in stale["items"]:
        item["id"]["time"] = "2025-01-01T00:00:00Z"
    assert verdict(AUDIT, stale, "isAuditLoggingEnabled") == (False, "success")


def test_audit_other_application_not_measured():
    body = rebased_audit()
    for item in body["items"]:
        item["id"]["applicationName"] = "gmail"
    assert verdict(AUDIT, body, "isAuditLoggingEnabled") == (None, "error")


# ---- confirmPasswordPolicyEnforced ----------------------------------------------------------

def test_password_real_gmail_page_is_not_measured():
    real = fixture("google_policies_gmail_real_2026-09-25.json")
    assert verdict(PASSWORD, real, "confirmPasswordPolicyEnforced") == (None, "error")  # truncated
    real.pop("nextPageToken")
    assert verdict(PASSWORD, real, "confirmPasswordPolicyEnforced") == (None, "error")  # no password policy


def test_password_strong_everywhere_passes():
    assert verdict(PASSWORD, security_page(), "confirmPasswordPolicyEnforced") == (True, "success")
    assert verdict(PASSWORD, json.dumps(security_page()), "confirmPasswordPolicyEnforced") == (True, "success")


def test_password_one_weak_org_unit_fails():
    for field, bad in (("allowedStrength", "WEAK"), ("minimumLength", "6"),
                       ("enforceRequirementsAtLogin", "False")):
        body = security_page()
        find(body, "security.password", "orgUnits/servers")["setting"]["value"][field] = bad
        assert verdict(PASSWORD, body, "confirmPasswordPolicyEnforced") == (False, "success"), field


# ---- authTypesAllowed -----------------------------------------------------------------------

def test_factors_real_gmail_page_is_not_measured():
    real = fixture("google_policies_gmail_real_2026-09-25.json")
    assert verdict(FACTORS, real, "authTypesAllowed") == (None, "error")
    real.pop("nextPageToken")
    assert verdict(FACTORS, real, "authTypesAllowed") == (None, "error")


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


# ---- a read that proves nothing is Not evaluated, never Failed --------------------------------

REFUSAL = {"statusCode": 403, "message": "Forbidden"}
INTEGRATION_ERROR_STATUS = {"status": "error", "message": "Integration execution error"}


def not_evaluated(module, body):
    """Every criterion key None, and the failure on the channel Token-Service reads."""
    out = module.transform(body)
    inner = out["transformedResponse"]
    assert module.CRITERIA_KEY in inner, body
    assert all(value is None for value in inner.values()), (module.CRITERIA_KEY, body, inner)
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error", (module.CRITERIA_KEY, body)
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"]), body


def truncated_security_page():
    body = security_page()
    body["nextPageToken"] = "next-page-token"
    return body


def page_without(kind):
    body = security_page()
    body["policies"] = [p for p in body["policies"] if p["setting"]["type"] != "settings/" + kind]
    return body


COMMON_UNREADABLE = [
    pytest.param(ERROR, id="integration-error-body"),
    pytest.param(GOOGLE_ERROR, id="google-permission-denied"),
    pytest.param(REFUSAL, id="http-403-refusal"),
    pytest.param(INTEGRATION_ERROR_STATUS, id="status-error-envelope"),
    pytest.param({"apiResponse": GOOGLE_ERROR}, id="wrapped-google-error"),
    pytest.param({}, id="empty-object"),
    pytest.param([], id="empty-array"),
    pytest.param(None, id="none"),
    pytest.param("", id="empty-string"),
    pytest.param("{}", id="empty-object-string"),
    pytest.param("null", id="json-null"),
    pytest.param("[]", id="empty-array-string"),
    pytest.param("<html>Bad gateway</html>", id="html-string"),
    pytest.param("not json at all", id="plain-text"),
    pytest.param(b"\x00not json", id="binary-not-json"),
    pytest.param(b"", id="empty-bytes"),
    pytest.param(42, id="number"),
]


@pytest.mark.parametrize("body", COMMON_UNREADABLE)
@pytest.mark.parametrize("module", [AUDIT, PASSWORD, FACTORS], ids=lambda m: m.CRITERIA_KEY)
def test_unreadable_body_is_not_evaluated(module, body):
    not_evaluated(module, body)


@pytest.mark.parametrize("module", [PASSWORD, FACTORS], ids=lambda m: m.CRITERIA_KEY)
def test_empty_or_wrong_policy_list_is_not_evaluated(module):
    for body in ({"policies": []}, {"policies": None}, {"policies": "x"}, {"policies": {}},
                 {"policies": ["not a policy"]}, {"items": []}):
        not_evaluated(module, body)
        not_evaluated(module, json.dumps(body))


@pytest.mark.parametrize("module", [PASSWORD, FACTORS], ids=lambda m: m.CRITERIA_KEY)
def test_truncated_policy_page_is_not_evaluated(module):
    not_evaluated(module, truncated_security_page())
    not_evaluated(module, json.dumps(truncated_security_page()))
    not_evaluated(module, {"apiResponse": truncated_security_page()})


def test_page_without_the_setting_is_not_evaluated():
    not_evaluated(PASSWORD, page_without("security.password"))
    not_evaluated(FACTORS, page_without("security.two_step_verification_enforcement_factor"))


def test_audit_empty_or_partial_feed_is_not_evaluated():
    for body in ({"kind": "admin#reports#activities", "items": []},
                 {"kind": "admin#reports#activities"},
                 {"kind": "admin#reports#activities", "items": None},
                 {"kind": "admin#reports#activities", "items": ["not an event"]},
                 {"kind": "admin#reports#activities", "items": [{"id": {"applicationName": "admin"}}]},
                 {"items": [{"id": {"applicationName": "admin", "time": "2026-09-25T15:24:09Z"}}]}):
        not_evaluated(AUDIT, body)
        not_evaluated(AUDIT, json.dumps(body))


def test_audit_unparseable_time_is_not_evaluated():
    # The parser raises: the transform's own except path, reported on the channel the evaluator reads.
    body = {"kind": "admin#reports#activities",
            "items": [{"id": {"applicationName": "admin", "time": "not-a-time"}}]}
    not_evaluated(AUDIT, body)

