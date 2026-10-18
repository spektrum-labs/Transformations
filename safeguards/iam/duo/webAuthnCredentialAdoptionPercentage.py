# webAuthnCredentialAdoptionPercentage -- what share of Duo users has registered a WebAuthn (FIDO2 / passkey) credential?
#
# Source: GET /admin/v1/users (method getUsers, returnSpec {"response": [...]}). Duo returns webauthncredentials on every user
# object (empty list when none).
#
# A body with no user object (an object with user_id or username), or users none of which carries webauthncredentials,
# proves nothing -- an error collapses to the returnSpec default [], and a quiet tenant looks the same -- so it is
# Unevaluated (every key None, data-collection error), never 0.0: an empty, error or non-list body, an exception,
# Duo's 403 / 40301 refusal (names "Grant resource - Read", the Admin API permission Duo documents for
# GET /admin/v1/users) and any other handed-over vendor error (vendorErrorAsResponse). A real read still measures:
# users came back carrying webauthncredentials and none has an entry is a measured 0.0.

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
# "message": "Access forbidden"}; GET /admin/v1/users needs "Grant resource - Read" (Duo Admin API docs). That says
# nothing about the tenant's posture, so every key stays None (Unevaluated) and the error names the
# permission to grant. Any other handed-over refusal is Unevaluated with errorCode "vendor_refusal" and names
# no permission.
META = {"transformationId": "webAuthnCredentialAdoptionPercentage", "vendor": "Duo", "category": "iam"}
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant resource - Read"
REFUSAL_KEYS = ["webAuthnCredentialAdoptionPercentage", "totalUsers",
                "usersWithWebAuthnCredentials"]
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
    problem = ("No Duo user objects (user_id or username) carrying webauthncredentials could be read from the getUsers response (" + reason
               + "). An empty or failed read cannot show how many users have registered a WebAuthn credential, so this is not a posture result.")
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
    if not any(is_user_object(u) and "webauthncredentials" in u for u in users):
        return unreadable("no user object carries webauthncredentials")

    total_users = len(users)
    users_with_webauthn = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        creds = u.get("webauthncredentials")
        if isinstance(creds, list) and len(creds) > 0:
            users_with_webauthn = users_with_webauthn + 1

    if total_users > 0:
        pct = round((users_with_webauthn / total_users) * 100.0, 2)
    else:
        pct = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    input_summary = {
        "totalUsers": total_users,
        "usersWithWebAuthnCredentials": users_with_webauthn,
    }

    if total_users == 0:
        fail_reasons.append(
            "No user records were returned by getUsers, so WebAuthn credential adoption cannot be computed."
        )
        recommendations.append(
            "Verify the Duo Admin API credential has permission to list users and retry."
        )
    elif users_with_webauthn > 0:
        pass_reasons.append(
            f"{users_with_webauthn} of {total_users} users ({pct}%) have a non-empty webauthncredentials array, "
            f"indicating a registered WebAuthn (FIDO2/passkey) credential."
        )
        if pct < 100.0:
            recommendations.append(
                f"Only {pct}% of users have registered a WebAuthn credential. "
                f"Encourage remaining users to enroll a FIDO2/passkey authenticator in the Duo Prompt."
            )
    else:
        fail_reasons.append(
            f"0 of {total_users} users have any entries in their webauthncredentials array; "
            f"no WebAuthn (FIDO2/passkey) credentials are registered across the tenant."
        )
        recommendations.append(
            "Enable and promote WebAuthn/passkey enrollment for users via Duo's authentication methods policy."
        )

    result = {
        "webAuthnCredentialAdoptionPercentage": pct,
        "totalUsers": total_users,
        "usersWithWebAuthnCredentials": users_with_webauthn,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "webAuthnCredentialAdoptionPercentage",
            "vendor": "Duo",
            "category": "iam",
        },
    )
