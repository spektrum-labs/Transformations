"""
Transformation: isMFAEnforcedForUsers
Vendor: Google Workspace
Category: Email Security

Evidence: getUserMFAStatus, Directory API users.list (customer=my_customer), paged by the
definition (maxResults=500, pageToken/nextPageToken) so every user is read.
scope https://www.googleapis.com/auth/admin.directory.user.readonly

Rule (fail closed): true only when every ACTIVE user (not suspended, not archived) has
isEnforcedIn2Sv true, and there is at least one active user. False when a real user list was
read and an active user is not enforced. Google sends the booleans as the strings
"True"/"False", which are read as such.

A list that still carries nextPageToken or paginationTruncated is judged on what was read: an active
user already seen that states enforcement is off proves False, with the counts None because they are from
part of the tenant. Nothing read from a cut-short list can prove True.

Not measured (key and counts None, dataCollection error, so Token-Service shows Not evaluated,
never Failed): a list that still carries nextPageToken or paginationTruncated in which no active user
states enforcement is off, a list in which no active user states it is off and some state nothing, a list
with no active user (every tenant has some), a Google
error or refusal, a missing scope, a body that is not JSON or has no users list, and this
transform's own exception.

Previously: one enforced user passed the whole tenant, suspended users were counted, and a
direct isMFAEnforcedForUsers flag in the payload was trusted. The every-active-user rule and
the suspended-user exclusion follow Transformations PR #611; archived users
and the truncation rule are added here.
"""

import json
from datetime import datetime, timezone


#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isMFAEnforcedForUsers',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

CRITERIA_KEY = "isMFAEnforcedForUsers"
#: The supporting counts a measured result carries; an unmeasured result carries them as None too.
UNMEASURED_COUNTS = {"totalUsers": None, "mfaEnrolledUsers": None}
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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


def is_truncated(body):
    """True when the list still carries nextPageToken or the paginator marked the read as cut short."""
    if not isinstance(body, dict):
        return False
    return bool(str(body.get("nextPageToken") or "").strip()) or is_true(body.get("paginationTruncated"))


def enforcement_state(record):
    """True or False when the user record states whether 2-Step Verification is enforced; None when it does
    not (no field, null, blank or an unrecognised value). Silence is not "not enforced"."""
    value = record.get("isEnforcedIn2Sv")
    if value is True or value is False:
        return value
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text == "true":
        return True
    if text == "false":
        return False
    return None


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
    result = {CRITERIA_KEY: None}
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
                                result_extra=UNMEASURED_COUNTS)
        body = None
        if isinstance(data, list):
            body = {"users": data}
        elif isinstance(data, dict):
            body = find_dict_with(data, "users")
        if body is None or not isinstance(body.get("users"), list):
            return not_measured("Directory users list was not returned", validation,
                                result_extra=UNMEASURED_COUNTS)
        truncated = is_truncated(body) or is_truncated(data)

        active = [u for u in body["users"] if isinstance(u, dict) and not is_true(u.get("suspended")) and not is_true(u.get("archived"))]
        enforced = [u for u in active if enforcement_state(u) is True]
        enrolled = [u for u in active if is_true(u.get("isEnrolledIn2Sv"))]
        # Only a record that states "not enforced" counts against the control. A record that states
        # nothing is unknown: it could be enforced.
        missing = [str(u.get("primaryEmail") or u.get("id") or "unknown") for u in active if enforcement_state(u) is False]
        silent = [u for u in active if enforcement_state(u) is None]
        total = len([u for u in body["users"] if isinstance(u, dict)])
        if len(active) == 0:
            # Every tenant has active users, so a list with none cannot be trusted: that is a read that
            # could not answer, not a finding that enforcement is off.
            return not_measured("No active users were returned; enforcement could not be confirmed", validation,
                                result_extra=UNMEASURED_COUNTS)
        if truncated:
            # A user already seen that states enforcement is off proves False, whatever the rest of the list
            # holds. Nothing seen can prove True, because a later page could hold a user who is not
            # enforced. The counts come from part of the tenant, so they are None.
            if not missing:
                return not_measured("Directory users list was truncated (nextPageToken present) and no active user read so far "
                                    "states 2-Step Verification is off; enforcement not evaluated across all users",
                                    validation, "Enable paging on getUserMFAStatus", result_extra=UNMEASURED_COUNTS)
            shown = ", ".join(missing[:LIST_LIMIT]) + (" (and more)" if len(missing) > LIST_LIMIT else "")
            return create_response(
                result={CRITERIA_KEY: False, "totalUsers": None, "mfaEnrolledUsers": None},
                validation=validation,
                fail_reasons=["2-Step Verification is not enforced for %d active users read so far: %s (the user list was cut short, so no counts are given)" % (len(missing), shown)],
                recommendations=["Enforce 2-Step Verification for every organizational unit (Security > Authentication > 2-Step Verification)"],
                input_summary={"truncated": True})
        if not missing and silent:
            return not_measured("%d of %d active users do not state whether 2-Step Verification is enforced, and none "
                                "states that it is not; enforcement could not be confirmed" % (len(silent), len(active)),
                                validation, "Re-read the user list so every user reports isEnforcedIn2Sv",
                                result_extra=UNMEASURED_COUNTS)
        result_value = len(missing) == 0
        result = {CRITERIA_KEY: result_value, "totalUsers": len(active), "mfaEnrolledUsers": len(enforced)}
        summary = {"usersRead": total, "activeUsers": len(active), "enforced": len(enforced),
                   "enrolled": len(enrolled), "excludedSuspendedOrArchived": total - len(active)}
        if result_value:
            return create_response(result=result, validation=validation,
                                   pass_reasons=["2-Step Verification is enforced for all %d active users (%d enrolled; %d suspended or archived users excluded)" % (
                                       len(active), len(enrolled), total - len(active))],
                                   input_summary=summary)
        shown = ", ".join(missing[:LIST_LIMIT]) + (" (and more)" if len(missing) > LIST_LIMIT else "")
        reason = "2-Step Verification is not enforced for %d of %d active users: %s" % (len(missing), len(active), shown)
        if silent:
            reason = reason + " (%d more users do not state it)" % len(silent)
        return create_response(result=result, validation=validation, fail_reasons=[reason],
                               recommendations=["Enforce 2-Step Verification for every organizational unit (Security > Authentication > 2-Step Verification)"],
                               input_summary=summary)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None, "totalUsers": None, "mfaEnrolledUsers": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
