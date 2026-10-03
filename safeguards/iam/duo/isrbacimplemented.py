import json
from datetime import datetime

# isRBACImplemented -- does the Duo tenant delegate administration through roles?
#
# Source: GET /admin/v1/admins (method getAdmins, returnSpec {"response": [...]}). Each
# admin carries a role: Owner, Administrator, Application Manager, User Manager, Security
# Analyst, Help Desk, Billing, Phishing Manager or Read-only.
#
# Verdict: true when at least one admin holds a role other than Owner, i.e. administration
# is split into least-privilege roles rather than every admin holding full control.
# ownerAdminPercentage is the measure. A body with no admin object (admin_id) proves
# nothing and is reported as a data-collection error, never judged. An Admin API
# credential without "Grant administrators - Read" gets a 403 (code 40301) from Duo; when the method opts
# in to vendorErrorAsResponse it arrives as a marker and is reported Unevaluated, naming the permission.

KEY = "isRBACImplemented"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                    recommendations=None, input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Duo",
                "category": "iam",
            },
        },
    }



INACTIVE_STATUSES = ("disabled", "locked out", "pending deletion", "deleted")


def load(input):
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except ValueError:
            input = {}
    return extract_input(input)


def objects_with(data, id_field):
    """The list of vendor objects carrying id_field; None when the body holds no such object."""
    items = data
    if isinstance(data, dict):
        items = data.get("response")
        if items is None:
            items = data.get("data")
    if not isinstance(items, list):
        return None
    found = [x for x in items if isinstance(x, dict) and x.get(id_field) not in (None, "")]
    return found if found else None


def pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


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
REFUSAL_KEYS = ["isRBACImplemented", "adminCount", "ownerAdminPercentage"]
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


def transform(input):
    refusal = refusal_envelope(input)
    if refusal is not None:
        return refusal_unevaluated(refusal)
    data, validation = load(input)
    admins = objects_with(data, "admin_id")
    if admins is None:
        return create_response(
            result={KEY: False, "adminCount": 0, "ownerAdminPercentage": 0.0},
            validation=validation,
            api_errors=["No Duo administrator objects (admin_id) in the getAdmins response."],
        )

    roles = {}
    owners = 0
    unroled = 0
    for a in admins:
        role = str(a.get("role") or "").strip()
        if not role:
            unroled = unroled + 1
            continue
        roles[role] = roles.get(role, 0) + 1
        if role.lower() == "owner":
            owners = owners + 1

    delegated = sum(roles[r] for r in roles if r.lower() != "owner")
    summary = {
        "adminCount": len(admins),
        "ownerAdminCount": owners,
        "delegatedRoleAdminCount": delegated,
        "ownerAdminPercentage": pct(owners, len(admins)),
        "distinctRoleCount": len(roles),
        "adminsByRole": roles,
        "adminsWithoutRole": unroled,
    }
    result = {KEY: delegated > 0}
    result.update(summary)

    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["%d of %d Duo administrators hold a delegated role other than Owner (roles in use: %s)."
                          % (delegated, len(admins), ", ".join(sorted(roles)))],
        )
    return create_response(
        result=result, validation=validation, input_summary=summary,
        fail_reasons=["No Duo administrator holds a role other than Owner: %d of %d are Owners, %d carry no role."
                      % (owners, len(admins), unroled)],
        recommendations=["Assign least-privilege Duo admin roles (Administrator, User Manager, Help Desk, "
                         "Read-only) and keep Owner for the few who need full control."],
    )
