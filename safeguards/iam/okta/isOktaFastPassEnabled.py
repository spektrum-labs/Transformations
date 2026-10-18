# isOktaFastPassEnabled.py - Okta Identity Engine
#
# Method: workflow getAuthenticatorPosture (Integration-Service #1454):
#   GET /api/v1/authenticators                              -> authenticators        (one list)
#   GET /api/v1/authenticators/{authenticatorId}/methods    -> authenticatorMethods  (one list per authenticator, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/
#   Authenticator.{id, key, status}; key "okta_verify" is Okta Verify.
#   listAuthenticatorMethods -> [{type, status, settings}]; type "signed_nonce" is Okta FastPass.
#
# Why not /api/v1/org/factors: on an Identity Engine org that Classic Engine catalogue is frozen and can
# disagree with the authenticators that are really on (IS #1454, measured 2026-10-05). It also has no
# FastPass row of its own. FastPass is a method of the Okta Verify authenticator.


def transform(input):
    """
    isOktaFastPassEnabled: True when Okta FastPass can be used to sign in. That means the Okta Verify
    authenticator (key okta_verify) is ACTIVE and its signed_nonce method is ACTIVE.

    False when the authenticator list was read and one of these holds: Okta Verify is not there, Okta
    Verify is not ACTIVE, or Okta Verify's method list was read and signed_nonce is missing or not
    ACTIVE.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body; the
    authenticator list is missing or empty (every Identity Engine org has at least a password or email
    authenticator); the method lists do not line up with the authenticators; Okta Verify is ACTIVE but its
    method list could not be read (a 403 on the sub-resource, for example); or the transformation errors.

    Does not prove: that any user has enrolled FastPass, or that a sign-in policy requires it.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    ok = state["enabled"]
    passes = [state["summary"]] if ok else []
    fails = [] if ok else [state["summary"]]
    return respond(ok, passes, fails, state["inputSummary"])


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def as_dict(value):
    return value if isinstance(value, dict) else {}


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and "authenticators" not in value:
            value = value[wrapper]
    return value


def error_in(data):
    if not isinstance(data, dict):
        return "Response is not an object with an authenticator list"
    for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
        if data.get(k):
            return "Okta returned an error: " + text(data.get(k))[:200]
    for k in ["statusCode", "status_code"]:
        if data.get(k) not in (None, 200):
            return "Okta returned HTTP " + text(data.get(k))
    return None


def item_list(item):
    """A list of objects, or None when the entry is an error body or unreadable."""
    if isinstance(item, dict):
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if item.get(k):
                return None
        for wrapper in ["apiResponse", "response", "result", "data"]:
            if wrapper in item:
                return item_list(item[wrapper])
        return None
    if isinstance(item, list):
        if [x for x in item if not isinstance(x, dict)]:
            return None
        return item
    return None


def evaluate(raw):
    state = {"error": None, "enabled": False, "summary": "", "inputSummary": {}}
    data = parse(raw)
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    authenticators = item_list(data.get("authenticators"))
    if authenticators is None:
        state["error"] = "The authenticator list is missing or unreadable"
        return state
    if not authenticators:
        state["error"] = "Okta returned no authenticators, so the authenticator list was not read"
        return state
    verify_index = None
    for index in range(len(authenticators)):
        if text(authenticators[index].get("key")).lower() == "okta_verify":
            verify_index = index
            break
    keys = sorted([text(a.get("key")) for a in authenticators if text(a.get("status")).upper() == "ACTIVE"])
    state["inputSummary"] = {"authenticators": len(authenticators), "activeAuthenticators": keys}
    if verify_index is None:
        state["summary"] = "Okta Verify is not configured, so FastPass cannot be used"
        return state
    verify = authenticators[verify_index]
    if text(verify.get("status")).upper() != "ACTIVE":
        state["summary"] = "Okta Verify is " + (text(verify.get("status")) or "not active") + ", so FastPass cannot be used"
        return state
    methods_by_authenticator = data.get("authenticatorMethods")
    if not isinstance(methods_by_authenticator, list) or len(methods_by_authenticator) != len(authenticators):
        state["error"] = "Okta Verify is active, but the authenticator method lists are missing or do not line up with the authenticators"
        return state
    methods = item_list(methods_by_authenticator[verify_index])
    if methods is None:
        state["error"] = "Okta Verify is active, but its method list could not be read"
        return state
    if not methods:
        state["error"] = "Okta Verify is active, but Okta returned no methods for it"
        return state
    statuses = {}
    for method in methods:
        statuses[text(method.get("type")).lower()] = text(method.get("status")).upper()
    state["inputSummary"] = {"authenticators": len(authenticators), "activeAuthenticators": keys,
                             "oktaVerifyMethods": sorted([k + ":" + statuses[k] for k in statuses])}
    signed_nonce = statuses.get("signed_nonce")
    if signed_nonce == "ACTIVE":
        state["enabled"] = True
        state["summary"] = "Okta Verify is active and its FastPass method (signed_nonce) is active"
    elif signed_nonce is None:
        state["summary"] = "Okta Verify is active, but it has no FastPass method (signed_nonce)"
    else:
        state["summary"] = "Okta Verify is active, but its FastPass method (signed_nonce) is " + signed_nonce
    return state


def respond(ok, passes, fails, summary):
    from datetime import datetime
    return {
        "transformedResponse": {"isOktaFastPassEnabled": ok},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if ok else
                           ["Activate the Okta Verify authenticator and turn on its FastPass method"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isOktaFastPassEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"isOktaFastPassEnabled": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isOktaFastPassEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }
