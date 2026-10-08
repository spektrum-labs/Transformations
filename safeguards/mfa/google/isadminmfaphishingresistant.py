"""
Transformation: isAdminMFAPhishingResistant
Vendor: Google Workspace  |  Integration: Google - MFA (5cdba755)  |  Category: Multifactor Authentication

Evidence: workflow isAdminMFAPhishingResistant (two GETs, merged under output keys)
  users    <- getUserMFAStatus: Directory API users.list (customer=my_customer, paged by the definition).
              isAdmin (super admin), isDelegatedAdmin, isEnforcedIn2Sv, suspended, archived.
              Scope admin.directory.user.readonly.
  policies <- getPolicies: Cloud Identity Policy API policies.list. Setting
              settings/security.two_step_verification_enforcement_factor, value allowedSignInFactorSet:
              ALL | NO_TELEPHONY | PASSKEY_ONLY | PASSKEY_PLUS_SECURITY_CODE | PASSKEY_PLUS_IP_BOUND_SECURITY_CODE.
              Scope cloud-identity.policies.readonly.

Rule (administrators = active super admins and delegated admins):
  False when any administrator does not have 2-Step Verification enforced (isEnforcedIn2Sv), or when NO
        2-Step Verification factor policy restricts sign-in to passkeys / security keys (PASSKEY_ONLY):
        whichever policy applies to an administrator then permits a phishable factor.
  True  only when every administrator has 2-Step Verification enforced and EVERY factor policy in the
        tenant is PASSKEY_ONLY, so whichever one applies, administrators can sign in with passkeys /
        security keys only. PASSKEY_PLUS_SECURITY_CODE variants are not phishing-resistant (a backup
        security code can be phished) and do not count.
  Not evaluated (null, dataCollection error): either list missing, an error or missing scope, a list
        still carrying nextPageToken, no active administrator, no factor policy at all, an unknown factor
        value, or a MIX of PASSKEY_ONLY and weaker policies. A mix needs the administrator's org unit or
        group to pick the policy that applies, and users.list carries the org unit path while policies
        carry org unit IDs, so the transform does not guess which one wins.

Does not prove: phishing-resistant MFA for administrators of systems that do not sign in through Google.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isAdminMFAPhishingResistant"
FACTOR_SETTING = "security.two_step_verification_enforcement_factor"
RESISTANT = "PASSKEY_ONLY"
KNOWN_SETS = ["ALL", "NO_TELEPHONY", "PASSKEY_ONLY", "PASSKEY_PLUS_SECURITY_CODE", "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE"]
SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client", "insufficient authentication scopes",
               "access_token_scope_insufficient", "request had insufficient authentication"]
WRAPPERS = ["apiResponse", "api_response", "response", "result", "Output", "data"]


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Google Workspace", "category": "MFA"},
        },
    }


def not_evaluated(reason, summary=None):
    return create_response({CRITERIA_KEY: None}, api_errors=[reason], fail_reasons=["Not evaluated: " + reason],
                           input_summary=summary)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def is_true(value):
    """Google bodies can reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def error_text(body):
    if body is None:
        return "no response body"
    if not isinstance(body, dict):
        return ""
    value = body.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [body.get("message"), body.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = body.get("statusCode", body.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, body.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(body.get("status", "")).lower() == "error":
        return str(body.get("message") or "integration error")
    return ""


def unwrap(body):
    for attempt in range(3):
        if not isinstance(body, dict) or "users" in body or "policies" in body:
            return body
        moved = False
        for key in WRAPPERS:
            if isinstance(body.get(key), dict):
                body = body[key]
                moved = True
                break
        if not moved:
            return body
    return body


def listed(part, name):
    """(list, None) for the paged list under `name`, or (None, reason)."""
    part = decode(part)
    text = error_text(part)
    if text:
        for hint in SCOPE_HINTS:
            if hint in text.lower():
                return None, "%s: scope not granted (%s)" % (name, text[:200])
        return None, "%s: %s" % (name, text[:240])
    if isinstance(part, dict) and not isinstance(part.get(name), list):
        for value in part.values():
            if isinstance(value, dict) and isinstance(value.get(name), list):
                part = value
                break
    if not isinstance(part, dict) or not isinstance(part.get(name), list):
        return None, "the %s list was not returned" % name
    if part.get("nextPageToken"):
        return None, "the %s list was truncated (nextPageToken present)" % name
    return [x for x in part[name] if isinstance(x, dict)], None


def factor_value(policy):
    setting = policy.get("setting") or {}
    if not isinstance(setting, dict) or not str(setting.get("type", "")).endswith(FACTOR_SETTING):
        return None
    value = setting.get("value") or {}
    return str(value.get("allowedSignInFactorSet")) if isinstance(value, dict) else "None"


def names(users, limit=10):
    shown = [str(u.get("primaryEmail") or u.get("id") or "unknown") for u in users]
    return ", ".join(shown[:limit]) + (" (and more)" if len(shown) > limit else "")


def transform(input):
    try:
        body = unwrap(decode(input))
        text = error_text(body)
        if text:
            return not_evaluated(text[:300])
        if not isinstance(body, dict) or "users" not in body or "policies" not in body:
            return not_evaluated("the workflow did not return both the Directory users list and the policies list")
        users, why = listed(body.get("users"), "users")
        if users is None:
            return not_evaluated(why)
        policies, why = listed(body.get("policies"), "policies")
        if policies is None:
            return not_evaluated(why)

        active = [u for u in users if not is_true(u.get("suspended")) and not is_true(u.get("archived"))]
        admins = [u for u in active if is_true(u.get("isAdmin")) or is_true(u.get("isDelegatedAdmin"))]
        values = [v for v in (factor_value(p) for p in policies) if v is not None]
        summary = {"activeAdmins": len(admins), "factorPolicies": len(values),
                   "passkeyOnlyPolicies": len([v for v in values if v == RESISTANT])}
        if not admins:
            return not_evaluated("no active administrator was returned", summary)
        unenforced = [u for u in admins if not is_true(u.get("isEnforcedIn2Sv"))]
        summary["adminsWithout2SvEnforced"] = len(unenforced)
        if unenforced:
            return create_response({CRITERIA_KEY: False}, input_summary=summary, fail_reasons=[
                "2-Step Verification is not enforced for %d of %d active administrators: %s" % (
                    len(unenforced), len(admins), names(unenforced))],
                recommendations=["Enforce 2-Step Verification with passkeys / security keys only for every "
                                 "administrator (Security > Authentication > 2-Step Verification)"])
        if not values:
            return not_evaluated("no 2-Step Verification factor policy was returned", summary)
        unknown = sorted(set(v for v in values if v not in KNOWN_SETS))
        if unknown:
            return not_evaluated("unknown allowedSignInFactorSet value(s): " + ", ".join(unknown), summary)
        strong = [v for v in values if v == RESISTANT]
        if len(strong) == len(values):
            return create_response({CRITERIA_KEY: True}, input_summary=summary, pass_reasons=[
                "All %d active administrators have 2-Step Verification enforced and all %d factor policies allow "
                "passkeys / security keys only" % (len(admins), len(values))])
        if not strong:
            weaker = sorted(set(values))
            return create_response({CRITERIA_KEY: False}, input_summary=summary, fail_reasons=[
                "No 2-Step Verification factor policy restricts sign-in to passkeys / security keys; the %d "
                "policies allow %s, so administrators can sign in with phishable factors" % (
                    len(values), ", ".join(weaker))],
                recommendations=["Set 'Allowed methods' to 'Only security key' for the org units or groups that "
                                 "hold administrator accounts (Security > Authentication > 2-Step Verification)"])
        return not_evaluated("%d of %d factor policies are passkey-only and the rest are weaker; which one applies "
                             "to each administrator needs org unit IDs that users.list does not carry" % (
                                 len(strong), len(values)), summary)
    except Exception as e:
        # dataCollection.status is the only channel the evaluator reads, and it is derived
        # from api_errors: without it a None verdict is graded FAILED, not Not evaluated.
        return create_response({CRITERIA_KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: %s" % str(e)[:200]],
                               fail_reasons=["Transformation error: %s" % str(e)])
