"""
Transformation: isMFAEnforcedForUsers
Vendor: Google Workspace
Category: Email Security

Evidence: getUserMFAStatus, Directory API users.list (customer=my_customer), paged by the
definition (maxResults=500, pageToken/nextPageToken) so every user is read.
scope https://www.googleapis.com/auth/admin.directory.user.readonly

Rule (fail closed): true only when every ACTIVE user (not suspended, not archived) has
isEnforcedIn2Sv true, and there is at least one active user. Google sends the booleans as the
strings "True"/"False", which are read as such. A list that still carries nextPageToken was
truncated, so the check is not measured rather than judged on part of the tenant. A Google
error, a missing scope or an unreadable body is also not measured.

Previously: one enforced user passed the whole tenant, suspended users were counted, and a
direct isMFAEnforcedForUsers flag in the payload was trusted. The every-active-user rule and
the suspended-user exclusion follow Transformations PR #611 (Simon Mullaney); archived users
and the truncation rule are added here.
"""

import json
from datetime import datetime, timezone

CRITERIA_KEY = "isMFAEnforcedForUsers"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
LIST_LIMIT = 10


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]


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
        parts = [str(x) for x in [data.get("message"), data.get("vendorAuthError"),
                                  data.get("error_description")] if x]
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


def vendor_error(data):
    """A clear reason when the body is an error, else None. A missing scope in the customer's
    domain-wide delegation grant is named as such, never read as a finding."""
    text = error_text(data)
    if not text:
        return None
    low = text.lower()
    if "missing_credentials" in low:
        return "Google Workspace admin email (subject) is not connected"
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("scope not granted: add %s to Spektrum's domain-wide delegation grant "
                    "(client ID 117073617964097263607) in the Google Admin console. Google said: %s"
                    % (REQUIRED_SCOPE, text[:240]))
    if "service_disabled" in low or "has not been used in project" in low:
        return "Google API not enabled for Spektrum's service account project: %s" % text[:240]
    return text[:300]


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def find_dict_with(data, key, depth=0):
    """The first dict (breadth-first through dict values, depth-limited) that has `key`."""
    frontier = [data]
    for level in range(5):
        next_frontier = []
        for node in frontier:
            if isinstance(node, dict):
                if key in node:
                    return node
                for value in node.values():
                    if isinstance(value, dict):
                        next_frontier.append(value)
        frontier = next_frontier
    return None


def not_measured(reason, validation, recommendation=None, result_extra=None):
    result = {CRITERIA_KEY: False}
    for k in (result_extra or {}):
        result[k] = result_extra[k]
    return create_response(
        result=result,
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        recommendations=[recommendation] if recommendation else []
    )


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)

        error = vendor_error(data)
        if error is not None:
            return not_measured(error, validation, "Check Spektrum's domain-wide delegation grant and re-evaluate",
                                result_extra={"totalUsers": 0, "mfaEnrolledUsers": 0})
        body = None
        if isinstance(data, list):
            body = {"users": data}
        elif isinstance(data, dict):
            body = find_dict_with(data, "users")
        if body is None or not isinstance(body.get("users"), list):
            return not_measured("Directory users list was not returned", validation,
                                result_extra={"totalUsers": 0, "mfaEnrolledUsers": 0})
        if body.get("nextPageToken"):
            return not_measured("Directory users list was truncated (nextPageToken present); enforcement not evaluated across all users",
                                validation, "Enable paging on getUserMFAStatus", result_extra={"totalUsers": len(body["users"]), "mfaEnrolledUsers": 0})

        active = [u for u in body["users"] if isinstance(u, dict) and not is_true(u.get("suspended")) and not is_true(u.get("archived"))]
        enforced = [u for u in active if is_true(u.get("isEnforcedIn2Sv"))]
        enrolled = [u for u in active if is_true(u.get("isEnrolledIn2Sv"))]
        missing = [str(u.get("primaryEmail") or u.get("id") or "unknown") for u in active if not is_true(u.get("isEnforcedIn2Sv"))]
        total = len(body["users"])
        result_value = len(active) > 0 and len(enforced) == len(active)
        result = {CRITERIA_KEY: result_value, "totalUsers": len(active), "mfaEnrolledUsers": len(enforced)}
        summary = {"usersRead": total, "activeUsers": len(active), "enforced": len(enforced),
                   "enrolled": len(enrolled), "excludedSuspendedOrArchived": total - len(active)}
        if result_value:
            return create_response(result=result, validation=validation,
                                   pass_reasons=["2-Step Verification is enforced for all %d active users (%d enrolled; %d suspended or archived users excluded)" % (
                                       len(active), len(enrolled), total - len(active))],
                                   input_summary=summary)
        if len(active) == 0:
            reason = "No active users were returned; enforcement could not be confirmed"
        else:
            shown = ", ".join(missing[:LIST_LIMIT]) + (" (and more)" if len(missing) > LIST_LIMIT else "")
            reason = "2-Step Verification is not enforced for %d of %d active users: %s" % (len(missing), len(active), shown)
        return create_response(result=result, validation=validation, fail_reasons=[reason],
                               recommendations=["Enforce 2-Step Verification for every organizational unit (Security > Authentication > 2-Step Verification)"],
                               input_summary=summary)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False, "totalUsers": 0, "mfaEnrolledUsers": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
