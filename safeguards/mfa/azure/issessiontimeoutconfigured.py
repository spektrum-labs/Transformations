"""
Transformation: isSessionTimeoutConfigured
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management
API: GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies  (Policy.Read.All)
Docs: https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol
      https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime

Question (CMMC SC.L2-3.13.9, criteriaValue lessThanOrEqual 480): after how many MINUTES must every user
sign in again? The value is a number of minutes, so the requirement's threshold decides.

How the number is derived:
  * Only ENFORCED policies (state == "enabled") that apply to every user (conditions.users.includeUsers
    contains "All") and every cloud app (conditions.applications.includeApplications contains "All") and
    carry sessionControls.signInFrequency with isEnabled == true.
  * signInFrequency {value, type: "hours"|"days"} -> minutes; frequencyInterval "everyTime" -> 0.
  * When several such policies exist, Entra applies the most restrictive one, so the minimum is reported.
  * When none exists, Entra's documented default applies: "The Microsoft Entra ID default configuration
    for user sign-in frequency is a rolling window of 90 days" -> 129600 minutes. That is a real
    measurement of an unconfigured tenant (and fails a 480-minute requirement), not a guess.

Output (numbers first): isSessionTimeoutConfigured (minutes), sessionTimeoutMinutes, qualifyingPolicyCount,
usingDefault.

Fails closed (None with dataCollection.status "error"): no policy list, an error body, an unrecognised body,
a qualifying policy whose frequency cannot be read, or a partial page (@odata.nextLink) with no qualifying
policy on it (the default cannot be asserted from a partial list).
"""
import json
from datetime import datetime

KEY = "isSessionTimeoutConfigured"
DEFAULT_MINUTES = 90 * 24 * 60
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "azure_issessiontimeoutconfigured",
                         "vendor": "Microsoft Entra ID", "category": "Identity and Access Management"},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None, "sessionTimeoutMinutes": None}, validation=validation,
                           api_errors=[reason], fail_reasons=[reason])


def unwrap(data):
    for attempt in range(6):
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except ValueError:
                return None
        if not isinstance(data, dict) or "value" in data or "conditionalAccessPolicies" in data:
            return data
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            return data
    return data


def policy_collection(data):
    data = unwrap(data)
    if isinstance(data, dict) and isinstance(data.get("conditionalAccessPolicies"), dict):
        data = data["conditionalAccessPolicies"]
    if not isinstance(data, dict) or data.get("error") or data.get("errors"):
        return None, False
    policies = data.get("value")
    if not isinstance(policies, list):
        return None, False
    if policies == [] and "conditionalAccess" not in str(data.get("@odata.context") or ""):
        return None, False
    return [p for p in policies if isinstance(p, dict)], bool(data.get("@odata.nextLink"))


def listed(block, name):
    if not isinstance(block, dict):
        return []
    value = block.get(name)
    return value if isinstance(value, list) else []


def applies_to_everyone(policy):
    conditions = policy.get("conditions")
    if not isinstance(conditions, dict):
        return False
    return "All" in listed(conditions.get("users"), "includeUsers") and \
        "All" in listed(conditions.get("applications"), "includeApplications")


def frequency_minutes(control):
    """-> minutes, or None when the control is present but unreadable."""
    if str(control.get("frequencyInterval") or "") == "everyTime":
        return 0
    unit = str(control.get("type") or "").lower()
    value = control.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    if unit == "hours":
        return int(value * 60)
    if unit == "days":
        return int(value * 1440)
    return None


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        validation = {"status": "unknown", "errors": [], "warnings": []}
        data = input
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input.get("data")
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
        policies, partial = policy_collection(data)
        if policies is None:
            return not_measured("No Conditional Access policy list was returned (error or unrecognised body)", validation)
        found = []
        for policy in policies:
            if str(policy.get("state") or "") != "enabled" or not applies_to_everyone(policy):
                continue
            session = policy.get("sessionControls")
            control = session.get("signInFrequency") if isinstance(session, dict) else None
            if not isinstance(control, dict) or control.get("isEnabled") is not True:
                continue
            minutes = frequency_minutes(control)
            if minutes is None:
                return not_measured("A sign-in frequency control could not be read (policy "
                                    + str(policy.get("displayName") or policy.get("id")) + ")", validation)
            found.append((minutes, str(policy.get("displayName") or policy.get("id") or "unnamed")))
        summary = {"policyCount": len(policies), "partialPage": partial}
        if not found:
            if partial:
                return not_measured("Only a partial page of Conditional Access policies was returned; the default "
                                    "session lifetime cannot be asserted", validation)
            result = {KEY: DEFAULT_MINUTES, "sessionTimeoutMinutes": DEFAULT_MINUTES, "qualifyingPolicyCount": 0,
                      "usingDefault": True}
            return create_response(result, validation,
                                   fail_reasons=["No enforced Conditional Access policy sets a sign-in frequency for all "
                                                 "users and all apps; Entra's default rolling 90-day window applies "
                                                 "(129600 minutes)"],
                                   recommendations=["Add an enforced Conditional Access policy for all users and all cloud "
                                                    "apps with a sign-in frequency session control"],
                                   input_summary=summary)
        shortest = min([m for m, n in found])
        names = [n for m, n in found if m == shortest]
        result = {KEY: shortest, "sessionTimeoutMinutes": shortest, "qualifyingPolicyCount": len(found),
                  "usingDefault": False}
        return create_response(result, validation,
                               pass_reasons=["Sign-in frequency for all users and all apps: " + str(shortest)
                                             + " minutes (policy " + ", ".join(names[:3]) + ")"],
                               input_summary=summary)
    except Exception as e:
        return not_measured("Transformation error: " + str(e))
