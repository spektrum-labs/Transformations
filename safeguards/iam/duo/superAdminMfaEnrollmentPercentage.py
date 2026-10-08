import json
from datetime import datetime


def extract_input(input_data):
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


# Integration-Service hands a vendor refusal over as data when the method opts in
# (vendorErrorAsResponse): {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}.
# Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
# "message": "Access forbidden"}. That says nothing about the tenant's posture, so every key stays None
# (Unevaluated) and the error names the permission to grant. Any other handed-over refusal is Unevaluated
# with errorCode "vendor_refusal" and names no permission.
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant administrators - Read"
REFUSAL_KEYS = ["superAdminMfaEnrollmentPercentage", "totalSuperAdmins", "enrolledSuperAdmins"]
REFUSAL_ENDPOINT = "GET /admin/v1/admins"


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


def refusal_unevaluated(envelope):
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
    out = create_response(result, None, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation])
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        collection["requiredPermission"] = REQUIRED_PERMISSION
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def unreadable(reason):
    """Nothing was measured: every key None, never 0."""
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    problem = ("No Duo administrator objects could be read from the getAdmins response (" + reason
               + "). A Duo account always has an Owner, so this is a failed or empty read, not 0% of super admins enrolled.")
    return create_response(
        result=result, api_errors=[problem], fail_reasons=[problem],
        recommendations=["Confirm the Duo Admin API credentials are valid and the Admin API application "
                         "has the \"" + REQUIRED_PERMISSION + "\" permission."],
        metadata={"transformationId": "superAdminMfaEnrollmentPercentage", "vendor": "Duo",
                  "category": "Multifactor Authentication"},
    )


def is_admin_object(a):
    return isinstance(a, dict) and any(a.get(f) not in (None, "") for f in ("admin_id", "role", "role_id"))


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


def transform(input):
    try:
        refusal = refusal_envelope(input)
        if refusal is not None:
            return refusal_unevaluated(refusal)
        return measure(input)
    except Exception:
        return unreadable("the response could not be processed")


def measure(input):
    if isinstance(input, bytes):
        try:
            input = input.decode("utf-8")
        except Exception:
            return unreadable("body is not valid UTF-8")
    if isinstance(input, str):
        try:
            input = json.loads(input)
        except ValueError:
            return unreadable("body is not valid JSON")
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        admins = data
    elif isinstance(data, dict):
        admins = data.get("response") or data.get("data") or []
        if not isinstance(admins, list):
            admins = []
    else:
        admins = []

    if not any(is_admin_object(a) for a in admins):
        return unreadable("empty, error or unrecognised body")

    super_admin_roles = ["owner", "administrator"]
    super_admins = []
    for a in admins:
        if not isinstance(a, dict):
            continue
        role_id = (a.get("role_id") or "").lower()
        role = (a.get("role") or "").lower()
        if role_id in super_admin_roles or role in super_admin_roles:
            super_admins.append(a)

    total_super = len(super_admins)

    def is_mfa_enrolled(admin):
        phone_details = admin.get("phone_details") or []
        if isinstance(phone_details, list):
            for p in phone_details:
                if isinstance(p, dict) and p.get("activated") is True:
                    return True
        webauthn = admin.get("webauthncredentials") or []
        if isinstance(webauthn, list) and len(webauthn) > 0:
            return True
        hardtoken = admin.get("hardtoken")
        if hardtoken:
            return True
        return False

    enrolled_super_admins = [a for a in super_admins if is_mfa_enrolled(a)]
    enrolled_count = len(enrolled_super_admins)

    if total_super == 0:
        percentage = 0
    else:
        percentage = round((enrolled_count / total_super) * 100.0, 2)

    enrolled_names = [a.get("name") or a.get("email") or a.get("admin_id") for a in enrolled_super_admins]
    not_enrolled_names = [
        account_name(a, ("email", "name", "admin_id"))
        for a in super_admins if a not in enrolled_super_admins
    ]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_super == 0:
        fail_reasons.append("No super admin (Owner/Administrator role) accounts were found in the getAdmins response.")
        recommendations.append("Verify that at least one Duo admin holds the Owner or Administrator role and has an MFA device enrolled.")
    elif enrolled_count == total_super:
        pass_reasons.append(
            f"All {total_super} super admin accounts ({', '.join([str(n) for n in enrolled_names])}) "
            f"have an active phone (activated=true), a registered webauthncredential, or a hardware token."
        )
    else:
        pass_reasons.append(
            f"{enrolled_count} of {total_super} super admin accounts have an enrolled MFA device."
        )
        fail_reasons.append(
            f"{total_super - enrolled_count} of {total_super} super admin accounts lack an enrolled MFA device; "
            + affected_line("Owner and Administrator roles", not_enrolled_names, total_super,
                            "super admins have no MFA device enrolled")
        )
        recommendations.append(
            "Enroll an MFA device (Duo Mobile push, phone callback, or WebAuthn security key) for each super admin account listed above."
        )

    result = {
        "superAdminMfaEnrollmentPercentage": percentage,
        "totalSuperAdmins": total_super,
        "enrolledSuperAdmins": enrolled_count,
    }

    input_summary = with_affected({
        "totalAdmins": len(admins),
        "totalSuperAdmins": total_super,
        "enrolledSuperAdmins": enrolled_count,
    }, not_enrolled_names)

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "superAdminMfaEnrollmentPercentage",
            "vendor": "Duo",
            "category": "Multifactor Authentication",
        },
    )
