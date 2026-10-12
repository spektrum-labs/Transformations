# isappconsentrestricted.py - Google Workspace
#
# Method: getApiControlsPolicies (Integration-Service), one GET:
#   GET https://cloudidentity.googleapis.com/v1/policies?filter=setting.type.matches('api_controls.*')&pageSize=100
# Docs: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings (API controls)
#   Scope https://www.googleapis.com/auth/cloud-identity.policies.readonly (domain-wide delegation).
#   Setting settings/api_controls.unconfigured_third_party_apps, field accessLevel:
#     BLOCK_ALL           - users cannot use unconfigured third-party apps
#     ALLOW_SIGN_IN_ONLY  - "Sign in with Google" only; no access to Google data
#     ACCESS_LEVEL_UNSPECIFIED - no restriction set (read as not restricted)
#   One policy per org unit or group where the setting is applied (policyQuery.orgUnit / group), type
#   ADMIN when an administrator set it and SYSTEM when it is Google's default.


def transform(input):
    """
    isAppConsentRestricted - True when every returned unconfigured-third-party-apps policy (the customer
    root and every org unit or group that overrides it) is BLOCK_ALL or ALLOW_SIGN_IN_ONLY, so users
    cannot grant an unreviewed app access to Workspace data.

    Also returns appConsentRestrictedPolicyPercentage: restricted policies / returned policies * 100.

    Fails closed on: an error body, no policies collection, and no unconfigured_third_party_apps policy
    in it (the setting must be shown before it can be judged).

    Does not prove: the per-app access list (apps marked trusted, limited or blocked), which this
    setting does not carry.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return respond(False, 0, [], ["Transformation error: " + str(e)], {}, [str(e)])
    if state["error"] is not None:
        return respond(False, 0, [], [state["error"]], {}, [])
    ok = state["total"] > 0 and state["restricted"] == state["total"]
    line = (str(state["restricted"]) + " of " + str(state["total"])
            + " unconfigured third-party app policies restrict access (BLOCK_ALL or ALLOW_SIGN_IN_ONLY)")
    if ok:
        return respond(True, state["percentage"], [line], [], state["inputSummary"], [])
    return respond(False, state["percentage"], [], [line] + state["open"][:10], state["inputSummary"], [])


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and "policies" not in value:
            value = value[wrapper]
    return value


def error_in(data):
    if not isinstance(data, dict):
        return "Response is not an object with a policies list"
    for k in ["error", "errors", "errorMessage", "errorCode"]:
        if data.get(k):
            return "Google returned an error: " + text(data.get(k))[:200]
    for k in ["statusCode", "status_code"]:
        if data.get(k) not in (None, 200):
            return "Google returned HTTP " + text(data.get(k))
    return None


def evaluate(raw):
    data = parse(raw)
    state = {"error": None, "total": 0, "restricted": 0, "percentage": 0, "open": [], "inputSummary": {}}
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    policies = data.get("policies")
    if not isinstance(policies, list):
        state["error"] = "No policies collection in the response: the API controls read cannot be shown to have run"
        return state
    found = []
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        setting = policy.get("setting") if isinstance(policy.get("setting"), dict) else {}
        if text(setting.get("type")).endswith("api_controls.unconfigured_third_party_apps"):
            found.append(policy)
    if not found:
        state["error"] = ("No api_controls.unconfigured_third_party_apps policy was returned ("
                          + str(len(policies)) + " policies read): third-party app access cannot be judged")
        return state
    restricted = 0
    for policy in found:
        value = policy["setting"].get("value") if isinstance(policy["setting"].get("value"), dict) else {}
        level = text(value.get("accessLevel")).upper()
        query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
        where = text(query.get("orgUnit") or query.get("group") or "customer") + " (" + text(policy.get("type")) + ")"
        if level in ["BLOCK_ALL", "ALLOW_SIGN_IN_ONLY"]:
            restricted = restricted + 1
        else:
            state["open"].append("Unconfigured third-party apps allowed at " + where + ": accessLevel " + (level or "missing"))
    state["total"] = len(found)
    state["restricted"] = restricted
    state["percentage"] = round(restricted * 100.0 / len(found), 1)
    state["inputSummary"] = {"unconfiguredAppPolicies": len(found), "restricted": restricted,
                             "appConsentRestrictedPolicyPercentage": state["percentage"]}
    return state


def respond(ok, percentage, passes, fails, summary, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"isAppConsentRestricted": ok, "appConsentRestrictedPolicyPercentage": percentage},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if ok else
                           ["In the Google Admin console, Security > Access and data control > API controls, set "
                            "unconfigured third-party apps to 'Don't allow' or 'Sign in with Google only' for every org unit"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isAppConsentRestricted", "vendor": "Google", "category": "Identity"},
        },
    }
