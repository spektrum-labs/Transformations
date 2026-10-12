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
    When another policy did not report its accessLevel, the open policy still proves False, and the
    percentage is None because the share cannot be computed from a policy that states nothing.
    A list still carrying nextPageToken (or paginationTruncated) is judged on what was read: a policy
    already seen that states open proves False, with the percentage None because it is from part of the
    list. A cut-short list in which no policy states open is not measured, since a later page could.

    Not measured (both keys None and a dataCollection error, so Token-Service shows Not evaluated, never
    Failed): an error or refusal body, a body that is not JSON or not an object, no policies collection,
    an empty list, no unconfigured_third_party_apps policy in it (the setting must be shown before it can
    be judged), a policy that does not report its accessLevel while no policy states open (it proves nothing
    about that policy), a list still carrying nextPageToken in which no policy states open (nothing read
    can show every policy is restricted), and this transform's own exception.

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
    if state["truncated"]:
        line = (str(len(state["open"])) + " unconfigured third-party app policies allow access; the policy list was cut "
                "short, so the rest were not read")
        return respond(False, state["percentage"], [], [line] + state["open"][:10], state["inputSummary"], [])
    line = (str(state["restricted"]) + " of " + str(state["total"])
            + " unconfigured third-party app policies restrict access (BLOCK_ALL or ALLOW_SIGN_IN_ONLY)")
    if state["unreported"]:
        line = line + "; " + str(state["unreported"]) + " did not report an access level"
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
    state = {"error": None, "total": 0, "restricted": 0, "unreported": 0, "truncated": False, "percentage": 0,
             "open": [], "inputSummary": {}}
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    policies = data.get("policies")
    if not isinstance(policies, list):
        state["error"] = "No policies collection in the response: the API controls read cannot be shown to have run"
        return state
    truncated = bool(text(data.get("nextPageToken"))) or truthy(data.get("paginationTruncated"))
    truncated_error = ("The policy list was truncated (nextPageToken present) and no policy read so far states "
                       "third-party app access is open: later pages could, and part of the list cannot show it is restricted")
    found = []
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        setting = policy.get("setting") if isinstance(policy.get("setting"), dict) else {}
        if text(setting.get("type")).endswith("api_controls.unconfigured_third_party_apps"):
            found.append(policy)
    if not found:
        state["error"] = truncated_error if truncated else (
            "No api_controls.unconfigured_third_party_apps policy was returned ("
            + str(len(policies)) + " policies read): third-party app access cannot be judged")
        return state
    restricted = 0
    unreported = []
    for policy in found:
        value = policy["setting"].get("value") if isinstance(policy["setting"].get("value"), dict) else {}
        level = text(value.get("accessLevel")).upper()
        if level == "":
            # A policy that does not report its access level proves nothing about that policy.
            query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
            unreported.append(text(query.get("orgUnit") or query.get("group") or "customer"))
            continue
        query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
        where = text(query.get("orgUnit") or query.get("group") or "customer") + " (" + text(policy.get("type")) + ")"
        if level in ["BLOCK_ALL", "ALLOW_SIGN_IN_ONLY"]:
            restricted = restricted + 1
        else:
            state["open"].append("Unconfigured third-party apps allowed at " + where + ": accessLevel " + level)
    if truncated:
        # A policy already seen that states open proves False, whatever the rest of the list holds. Nothing
        # seen can prove restricted, because a later page could hold an open policy. The share and the totals
        # come from part of the list, so they are None.
        if not state["open"]:
            state["error"] = truncated_error
            return state
        state["truncated"] = True
        state["percentage"] = None
        state["inputSummary"] = {"truncated": True, "openPolicies": len(state["open"])}
        return state
    if unreported and not state["open"]:
        # No policy states open and some state nothing: all-restricted cannot be shown, and neither can
        # an open policy. That is a read that could not answer.
        state["error"] = ("An unconfigured_third_party_apps policy did not report its accessLevel (" + ", ".join(unreported[:5])
                          + "): no policy states third-party app access is open, so it was not evaluated")
        return state
    state["total"] = len(found)
    state["restricted"] = restricted
    state["unreported"] = len(unreported)
    if unreported:
        # A policy that states open already proves False. The share of restricted policies needs every
        # policy's level, so it is None while any policy states nothing.
        state["percentage"] = None
        state["inputSummary"] = {"unconfiguredAppPolicies": len(found), "restricted": restricted,
                                 "openPolicies": len(state["open"]), "withoutAccessLevel": len(unreported),
                                 "appConsentRestrictedPolicyPercentage": None}
        return state
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
