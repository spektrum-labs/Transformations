"""
Transformation: mfa_transform
Vendor: Email Security Provider
Category: Identity / Authentication

Evaluates the MFA status for users in the organization.

Measured: a user list that was read (true when a user has 2-Step Verification enforced, false when
none does). The criterion is never read out of the payload: a vendor does not send it, so an
isMFAEnforcedForUsers field in the body is not evidence of anything.

Not measured (the key and the user counts are None, with a dataCollection error, so Token-Service
shows Not evaluated, never Failed): a refusal or error body, a body that is not JSON, no users list,
an empty user list, a list that still carries nextPageToken (or paginationTruncated) in which no user is
enforced yet (more pages could hold one), a failed input validation, and this transform's own
exception.

Counts: totalUsers and mfaEnrolledUsers count the user records of a complete list and are None for a
truncated one, because a count taken from part of the list is not a total. One enforced user already
proves True, so that verdict stays when the list was cut short.
"""

import json
from datetime import datetime

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


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "mfa_transform",
                "vendor": "Email Security Provider",
                "category": "Identity"
            }
        }
    }


def vendor_error(data):
    """Google's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if isinstance(data, str) and data.strip() == "":
        return "Empty response body"
    if not isinstance(data, dict):
        return None
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return str(value.get("message") or value.get("status") or value.get("code") or value)
        return "%s %s" % (value, data.get("message") or data.get("error_description") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return None


def is_truncated(body):
    """True when the list still carries nextPageToken or the paginator marked the read as cut short."""
    if not isinstance(body, dict):
        return False
    marker = body.get("paginationTruncated")
    return bool(str(body.get("nextPageToken") or "").strip()) or marker is True or str(marker).strip().lower() == "true"


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


def unmeasured(reason, validation, summary=None):
    """The read could not answer: the key and the counts are None and a dataCollection error says why."""
    return create_response(
        result={"isMFAEnforcedForUsers": None, "totalUsers": None, "mfaEnrolledUsers": None},
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        input_summary=summary
    )


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return unmeasured("Input validation failed", validation)

        error = vendor_error(data)
        if error is None and not isinstance(data, dict):
            error = "Response is not a user list"
        if error is not None:
            return unmeasured(error, validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        isMFAEnforcedForUsers = False
        total_users = 0
        mfa_enrolled_users = 0
        measured = False
        truncated = False
        silent_users = 0

        # The user list is the only evidence. The criterion itself is not read out of the body it judges.
        raw_data = data.get('rawResponse', data)

        if isinstance(raw_data, dict) and 'users' in raw_data:
            users = raw_data['users']
            if isinstance(users, list):
                # An empty list, or one with no user record in it, proves nothing either way.
                records = [obj for obj in users if isinstance(obj, dict)]
                measured = len(records) > 0
                if measured:
                    total_users = len(records)
                    mfa_enrolled = [obj for obj in records if enforcement_state(obj) is True]
                    mfa_enrolled_users = len(mfa_enrolled)
                    isMFAEnforcedForUsers = mfa_enrolled_users > 0
                    # A record that states nothing could be enforced: it is unknown, not "not enforced".
                    silent_users = len([obj for obj in records if enforcement_state(obj) is None])
                    truncated = is_truncated(raw_data) or is_truncated(data)

        if not measured:
            return unmeasured("No user list was read: an empty or unrecognised body cannot be told apart from a "
                              "read that returned nothing", validation)
        if truncated and not isMFAEnforcedForUsers:
            # More pages exist. One enforced user already decides True; with none enforced yet, a later page
            # could hold one.
            return unmeasured("The user list was truncated (nextPageToken present) before an enforced user was "
                              "found; enforcement not evaluated across all users", validation,
                              {"truncated": True})

        if not isMFAEnforcedForUsers and silent_users > 0:
            # No user states that enforcement is on, and some state nothing: False needs every record to
            # state that it is off.
            return unmeasured("%d of %d users do not state whether 2-Step Verification is enforced, and none states "
                              "that it is; enforcement could not be confirmed" % (silent_users, total_users), validation)

        # Counts are totals only for a complete list; a truncated list gives a partial page, so None.
        reported_total = None if truncated else total_users
        reported_enrolled = None if truncated else mfa_enrolled_users

        if isMFAEnforcedForUsers:
            if truncated:
                pass_reasons.append("MFA enforced for at least one user (the user list was cut short, so no counts are given)")
            elif total_users > 0:
                percentage = round((mfa_enrolled_users / total_users) * 100)
                pass_reasons.append(f"MFA enforced for {mfa_enrolled_users}/{total_users} users ({percentage}%)")
            else:
                pass_reasons.append("MFA enforcement is enabled")
        else:
            fail_reasons.append("MFA is not enforced for users")
            recommendations.append("Enable MFA enforcement (2-Step Verification) for all users")

        return create_response(
            result={
                criteriaKey: isMFAEnforcedForUsers,
                "totalUsers": reported_total,
                "mfaEnrolledUsers": reported_enrolled
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"truncated": True} if truncated else {
                "totalUsers": total_users,
                "mfaEnrolledUsers": mfa_enrolled_users
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None, "totalUsers": None, "mfaEnrolledUsers": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
