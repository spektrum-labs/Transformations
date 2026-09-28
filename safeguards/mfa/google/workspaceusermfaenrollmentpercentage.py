"""
Transformation: workspaceUserMfaEnrollmentPercentage
Vendor: Google Workspace  |  Integration: Google - MFA (5cdba755)

Evidence: getUserMFAStatus, Directory API users.list (customer=my_customer), paged by the definition
(maxResults=500, pageToken/nextPageToken). Scope admin.directory.user.readonly.
isAdmin is the documented super-administrator flag on the user resource.

Rule (fail closed): Percent of active users (not suspended, not archived) with isEnrolledIn2Sv true. None when there are no active users.
Google sends booleans as the strings "True"/"False". An error envelope, a missing scope,
no users list, or a list still carrying nextPageToken is not measured (None, dataCollection error).
"""

import json
from datetime import datetime

CRITERIA_KEY = "workspaceUserMfaEnrollmentPercentage"
NOT_MEASURED = None
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        for attempt in range(3):
            unwrapped = False
            for key in ["api_response", "response", "result", "apiResponse", "Output"]:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "Google Workspace", "category": "MFA"}
        }
    }


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else ""
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, data.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def active_users(input):
    """(active users, None) from the paged Directory users list, or (None, reason) when it cannot be
    measured: an error envelope, a missing scope, no users list, or a list still carrying nextPageToken."""
    if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
        input = None
    if isinstance(input, str):
        input = json.loads(input)
    elif isinstance(input, bytes):
        input = json.loads(input.decode("utf-8"))
    data, validation = extract_input(input)
    text = error_text(data)
    if text:
        for hint in SCOPE_HINTS:
            if hint in text.lower():
                return None, "scope not granted: add %s to Spektrum's domain-wide delegation grant. Google said: %s" % (REQUIRED_SCOPE, text[:240])
        return None, text[:300]
    body = {"users": data} if isinstance(data, list) else data
    if isinstance(body, dict) and not isinstance(body.get("users"), list):
        for value in body.values():
            if isinstance(value, dict) and isinstance(value.get("users"), list):
                body = value
                break
    if not isinstance(body, dict) or not isinstance(body.get("users"), list):
        return None, "Directory users list was not returned"
    if body.get("nextPageToken"):
        return None, "Directory users list was truncated (nextPageToken present); not evaluated across all users"
    return [u for u in body["users"] if isinstance(u, dict) and not is_true(u.get("suspended"))
            and not is_true(u.get("archived"))], None


def names(users, limit=10):
    shown = [str(u.get("primaryEmail") or u.get("id") or "unknown") for u in users]
    return ", ".join(shown[:limit]) + (" (and more)" if len(shown) > limit else "")


def transform(input):
    try:
        users, reason = active_users(input)
        if users is None:
            return create_response(result={CRITERIA_KEY: NOT_MEASURED}, api_errors=[reason],
                                   fail_reasons=["Not measured: " + reason])
        return evaluate(users)
    except Exception as e:
        return create_response(result={CRITERIA_KEY: NOT_MEASURED}, transformation_errors=[str(e)],
                               fail_reasons=["Transformation error: %s" % str(e)])

def evaluate(users):
    if not users:
        return create_response(result={CRITERIA_KEY: None}, api_errors=["No active users were returned"],
                               fail_reasons=["Not measured: no active users were returned"])
    enrolled = [u for u in users if is_true(u.get("isEnrolledIn2Sv"))]
    value = round(100.0 * len(enrolled) / len(users), 2)
    missing = [u for u in users if not is_true(u.get("isEnrolledIn2Sv"))]
    reason = "%d of %d active users are enrolled in 2-Step Verification (%s%%)" % (len(enrolled), len(users), value)
    return create_response(result={CRITERIA_KEY: value}, pass_reasons=[reason] if not missing else [],
                           fail_reasons=[reason + "; not enrolled: " + names(missing)] if missing else [],
                           input_summary={"activeUsers": len(users), "enrolled": len(enrolled)})
