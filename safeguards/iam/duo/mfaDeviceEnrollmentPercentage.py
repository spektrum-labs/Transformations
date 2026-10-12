# mfaDeviceEnrollmentPercentage -- what share of active Duo users has at least one enrolled
# authentication device?
#
# Source: GET /admin/v1/users (method getUsers, returnSpec {"response": [...]}). A user has a device when
# is_enrolled is true or phones, tokens, u2ftokens, webauthncredentials or desktop_authenticators is non-empty.
#
# A body with no user object (an object with user_id or username) proves nothing -- an error collapses to the
# returnSpec default [], and a quiet tenant looks the same -- so it is Unevaluated (every key None,
# data-collection error), never 0.0: an empty, error or non-list body, an exception, Duo's 403 / 40301
# refusal (names "Grant resource - Read", the Admin API permission Duo documents for GET /admin/v1/users) and
# any other handed-over vendor error (vendorErrorAsResponse). So are active users none of whom carries any
# enrollment field. A real read still measures: users came back and none has a device is a measured 0.0.

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


# #101: findings name the affected accounts (same shape as mfa/azure/legacyauthblocked.py). The first
# reason names at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most
# MAX_AFFECTED, with the full count in affectedAccountCount. The verdict never reads them.
MAX_NAMED = 20
MAX_AFFECTED = 50


def account_name(obj, fields):
    for field in fields:
        value = obj.get(field)
        if value not in (None, ""):
            return str(value).strip()[:100]
    return "unknown"


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def affected_line(scope, affected, total, what):
    """One line naming the tool and its scope: 'Duo (<scope>): N of M <what>: a, b and K more'."""
    return "Duo (%s): %d of %d %s: %s" % (scope, len(affected), total, what, name_list(affected))


def with_affected(summary, affected):
    summary["affectedAccounts"] = affected[:MAX_AFFECTED]
    summary["affectedAccountCount"] = len(affected)
    return summary


# Integration-Service hands a vendor refusal over as data when the method opts in
# (vendorErrorAsResponse): {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}.
# Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
# "message": "Access forbidden"}; GET /admin/v1/users needs "Grant resource - Read" (Duo Admin API docs). That says
# nothing about the tenant's posture, so every key stays None (Unevaluated) and the error names the
# permission to grant. Any other handed-over refusal is Unevaluated with errorCode "vendor_refusal" and names
# no permission.
META = {"transformationId": "mfaDeviceEnrollmentPercentage", "vendor": "Duo", "category": "iam"}
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant resource - Read"
REFUSAL_KEYS = ["mfaDeviceEnrollmentPercentage", "activeUsers", "usersWithEnrolledDevice"]
REFUSAL_ENDPOINT = "GET /admin/v1/users"


def refusal_decoded(body):
    """A vendor body or whole input as an object: dicts as they are, JSON text or bytes parsed, else None."""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except Exception:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return None
    return body


def refusal_envelope(value):
    """The dict carrying vendorErrorAsResponse: the input itself or one level inside it, else None."""
    value = refusal_decoded(value)
    if not isinstance(value, dict):
        return None
    if "vendorErrorAsResponse" in value:
        return value
    for k in value:
        inner = value[k]
        if isinstance(inner, dict) and "vendorErrorAsResponse" in inner:
            return inner
    return None


def refusal_unevaluated(envelope, validation=None):
    """Duo's refusal (or any other handed-over vendor error) as Unevaluated: every key None, never False."""
    marker = envelope.get("vendorErrorAsResponse")
    status = marker.get("status") if isinstance(marker, dict) else None
    body = refusal_decoded(marker.get("body")) if isinstance(marker, dict) else None
    forbidden = (status == 403 and isinstance(body, dict)
                 and body.get("code") == REFUSAL_FORBIDDEN_CODE and body.get("message") == "Access forbidden")
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    if forbidden:
        problem = ("PERMISSION-NOT-GRANTED: Duo refused the call to " + REFUSAL_ENDPOINT + " with HTTP 403 code 40301 "
                   "(Access forbidden) because the Admin API application lacks the \"" + REQUIRED_PERMISSION
                   + "\" permission. Nothing was measured; this is not a posture result.")
        recommendation = ("In the Duo Admin Panel, open the Admin API application used for Spektrum and enable the \""
                          + REQUIRED_PERMISSION + "\" permission; the integration key and secret do not change.")
    else:
        problem = ("Duo refused the call to " + REFUSAL_ENDPOINT + " (HTTP " + str(status)[:10]
                   + "); nothing was measured.")
        recommendation = "Confirm the Duo Admin API credentials are valid and the Admin API application is enabled."
    out = create_response(result, validation, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation], metadata=META)
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        collection["requiredPermission"] = REQUIRED_PERMISSION
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def unreadable(reason, validation=None):
    """Nothing was measured: every key None, never False or 0."""
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    problem = ("No Duo user objects (user_id or username) could be read from the getUsers response (" + reason
               + "). An empty or failed read cannot show how many users have a device enrolled, so this is not a posture result.")
    return create_response(
        result=result, validation=validation, api_errors=[problem], fail_reasons=[problem],
        recommendations=["Confirm the Duo Admin API credentials are valid and the Admin API application "
                         "has the \"" + REQUIRED_PERMISSION + "\" permission."], metadata=META,
    )


def parse_json(input):
    """JSON text or bytes as an object; text that is not JSON reads as an empty body."""
    if isinstance(input, (str, bytes)):
        try:
            return json.loads(input)
        except ValueError:
            return {}
    return input


def user_list(data):
    """The user list in a getUsers body (a list, or an object holding it under response or data), else []."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        users = data.get("response") or data.get("data") or []
        if isinstance(users, list):
            return users
    return []


def is_user_object(u):
    return isinstance(u, dict) and any(u.get(f) not in (None, "") for f in ("user_id", "username"))


def transform(input):
    try:
        refusal = refusal_envelope(input)
        data = None
        validation = None
        if refusal is None:
            data, validation = extract_input(parse_json(input))
            refusal = refusal_envelope(data)
        if refusal is not None:
            return refusal_unevaluated(refusal)
        return measure(data, validation)
    except Exception:
        return unreadable("the response could not be processed")


def measure(data, validation):
    if not isinstance(validation, dict):
        validation = None
    users = user_list(data)
    if not any(is_user_object(u) for u in users):
        return unreadable("empty, error or unrecognised body")

    inactive_statuses = ("disabled", "locked out", "deleted")

    total_active = 0
    active_with_device = 0
    unknown_device_signal = 0
    without_device = []

    for u in users:
        if not isinstance(u, dict):
            continue
        # Skip pure truncation-marker stub entries with no real user fields
        if "_truncated" in u and len(u.keys()) == 1:
            continue

        status_raw = u.get("status")
        is_known_inactive = False
        if status_raw:
            if str(status_raw).lower() in inactive_statuses:
                is_known_inactive = True
        if is_known_inactive:
            continue

        total_active = total_active + 1

        has_device = False
        has_any_signal = False

        if "is_enrolled" in u:
            has_any_signal = True
            if u.get("is_enrolled"):
                has_device = True

        for field in ("phones", "tokens", "u2ftokens", "webauthncredentials", "desktop_authenticators"):
            if field in u:
                has_any_signal = True
                val = u.get(field) or []
                if isinstance(val, list) and len(val) > 0:
                    has_device = True

        if not has_any_signal:
            unknown_device_signal = unknown_device_signal + 1

        if has_device:
            active_with_device = active_with_device + 1
        else:
            without_device.append(account_name(u, ("username", "email", "user_id")))

    if total_active > 0 and unknown_device_signal == total_active:
        return unreadable("no active user carries an enrollment field (is_enrolled, phones, tokens, u2ftokens, "
                          "webauthncredentials or desktop_authenticators)")

    percentage = 0.0
    if total_active > 0:
        percentage = round((active_with_device / total_active) * 100, 2)

    validation_errors = []
    if total_active == 0:
        validation_errors.append("No active users found in response - cannot compute enrollment percentage")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_active > 0:
        if active_with_device == total_active:
            pass_reasons.append(
                f"All {total_active} active Duo users have at least one enrolled authentication device "
                f"(is_enrolled=true or a non-empty phones/tokens/u2ftokens/webauthncredentials/desktop_authenticators array)."
            )
        elif active_with_device > 0:
            pass_reasons.append(
                f"{active_with_device} of {total_active} active Duo users ({percentage}%) have at least one "
                f"enrolled authentication device."
            )
        if active_with_device < total_active:
            missing = total_active - active_with_device
            fail_reasons.append(
                f"{missing} of {total_active} active Duo users show no enrolled authentication device "
                f"(is_enrolled=false/absent and empty phones/tokens/u2ftokens/webauthncredentials/desktop_authenticators); "
                + affected_line("active users", without_device, total_active, "active users have no MFA device enrolled")
            )
            recommendations.append(
                "Prompt the users lacking an enrolled MFA device to complete Duo enrollment "
                "(phone, hardware token, or WebAuthn/U2F key) before their next authentication."
            )
        if unknown_device_signal > 0:
            fail_reasons.append(
                f"{unknown_device_signal} of {total_active} active users had no device-related fields present in "
                f"the response payload at all (truncated/partial record), so their enrollment status could not be confirmed."
            )
    else:
        fail_reasons.append("No active users were found in the Duo user list; enrollment percentage could not be computed.")
        recommendations.append("Verify the getUsers API call is returning the tenant's active user population.")

    result = {
        "mfaDeviceEnrollmentPercentage": percentage,
        "activeUsers": total_active,
        "usersWithEnrolledDevice": active_with_device,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=with_affected({"activeUsers": total_active, "usersWithEnrolledDevice": active_with_device,
                                     "unknownDeviceSignal": unknown_device_signal}, without_device),
        transformation_errors=validation_errors if total_active == 0 else [],
        metadata={
            "transformationId": "mfaDeviceEnrollmentPercentage",
            "vendor": "Duo",
            "category": "iam",
        },
    )
