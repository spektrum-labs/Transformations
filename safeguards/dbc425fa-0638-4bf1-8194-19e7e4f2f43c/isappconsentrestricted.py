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

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isAppConsentRestricted', 'appConsentRestrictedPolicyPercentage')


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def transform(input):
    """
    isAppConsentRestricted - True when every returned unconfigured-third-party-apps policy (the customer
    root and every org unit or group that overrides it) is BLOCK_ALL or ALLOW_SIGN_IN_ONLY, so users
    cannot grant an unreviewed app access to Workspace data.

    Also returns appConsentRestrictedPolicyPercentage: restricted policies / returned policies * 100.

    False (measured) when unconfigured-third-party-apps policies were read and one is not restricted.

    Not measured (both keys None and a dataCollection error, so Token-Service shows Not evaluated, never
    Failed): an error or refusal body, a body that is not JSON or not an object, no policies collection,
    an empty list, no unconfigured_third_party_apps policy in it (the setting must be shown before it can
    be judged), a list still carrying nextPageToken (the share of restricted policies would be partial),
    and this transform's own exception.

    Does not prove: the per-app access list (apps marked trusted, limited or blocked), which this
    setting does not carry.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return respond(None, None, [], ["Transformation error: " + str(e)], {}, [str(e)])
    if state["error"] is not None:
        return respond(None, None, [], [state["error"]], {}, [], [state["error"]])
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


def truthy(value):
    return value is True or text(value).lower() == "true"


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
    if text(data.get("nextPageToken")) or truthy(data.get("paginationTruncated")):
        state["error"] = ("The policy list was truncated (nextPageToken present): the share of restricted "
                          "unconfigured third-party app policies cannot be computed from part of the list")
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


def respond(ok, percentage, passes, fails, summary, errors, api_errors=None):
    from datetime import datetime
    result = {"isAppConsentRestricted": ok, "appConsentRestrictedPolicyPercentage": percentage}
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and criteria_unmeasured(result):
        api_errors = list(fails or []) or list(errors or []) or [
            "The response could not answer this check, so it was not evaluated."]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors or []},
            "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if ok is not False else
                           ["In the Google Admin console, Security > Access and data control > API controls, set "
                            "unconfigured third-party apps to 'Don't allow' or 'Sign in with Google only' for every org unit"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isAppConsentRestricted", "vendor": "Google", "category": "Identity"},
        },
    }
