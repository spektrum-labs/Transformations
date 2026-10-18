# hasEmergencyAccessCodeAPIAccess -- can the integration read Duo emergency access (bypass) codes?
#
# Source: GET /admin/v1/users/{user_id}/bypass_codes, which Duo documents as needing "Grant resource - Read".
# Duo answers {"stat": "OK", "response": [...bypass code metadata...], "metadata": {...}}; the list is empty for a
# user with no bypass code, which is normal.
#
# Verdict: true when Duo answered a read. An empty list counts only with Duo's own "stat": "OK" envelope as
# proof (a failed read defaults to an empty list too). Anything that is not a read is Unevaluated (every key
# None, data-collection error), never False: an empty, error, non-list or unreadable body, an exception, Duo's
# 403 / 40301 refusal (names "Grant resource - Read") and any other handed-over vendor error
# (vendorErrorAsResponse). A refusal or a failed read cannot show the API is out of reach once the permission is
# granted, so this check has no measured False.

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
# "message": "Access forbidden"}; GET /admin/v1/users/{user_id}/bypass_codes needs "Grant resource - Read" (Duo Admin API docs). That says
# nothing about the tenant's posture, so every key stays None (Unevaluated) and the error names the
# permission to grant. Any other handed-over refusal is Unevaluated with errorCode "vendor_refusal" and names
# no permission.
META = {"transformationId": "hasEmergencyAccessCodeAPIAccess", "vendor": "Duo", "category": "iam"}
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant resource - Read"
REFUSAL_KEYS = ["hasEmergencyAccessCodeAPIAccess", "bypassCodeCount"]
REFUSAL_ENDPOINT = "GET /admin/v1/users/{user_id}/bypass_codes"


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
    problem = ("No Duo bypass code list could be read from the response of GET /admin/v1/users/{user_id}/bypass_codes (" + reason
               + "). An empty or failed read cannot show whether the credential can read emergency access codes, so this is not a posture result.")
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


def error_marked(body):
    """True when a dict body says it is an error (an Integration-Service envelope, a Duo FAIL body)."""
    if not isinstance(body, dict):
        return False
    stat = body.get("stat")
    status = body.get("status")
    return (body.get("error") not in (None, False) or "errorMessage" in body
            or body.get("success") is False
            or (isinstance(stat, str) and stat.upper() == "FAIL")
            or (isinstance(status, str) and status.lower() == "error"))


def success_proven(raw):
    """True only when the body itself shows Duo answered the read successfully.

    An empty list is what several failed reads look like (a collection layer defaulting to [], an error
    envelope carrying an empty list), so an empty read counts as a pass only with positive proof: Duo's own
    {"stat": "OK", "response": ...} envelope. A failed enriched validation is never proof."""
    body = raw
    for _ in range(4):
        if not isinstance(body, dict):
            return False
        if error_marked(body):
            return False
        if "data" in body and "validation" in body:
            validation = body.get("validation")
            if isinstance(validation, dict) and validation.get("status") == "failed":
                return False
            body = body.get("data")
            continue
        stat = body.get("stat")
        if isinstance(stat, str) and stat.upper() == "OK" and isinstance(body.get("response"), (list, dict)):
            return True
        moved = False
        for key in ("apiResponse", "api_response", "result", "response"):
            if isinstance(body.get(key), dict):
                body = body[key]
                moved = True
                break
        if not moved:
            return False
    return False


def response_items(data):
    """The list in a Duo body (a bare list, or an object holding it under response or data), else None."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("response")
        if items is None:
            items = data.get("data")
        if isinstance(items, list):
            return items
    return None


def transform(input):
    try:
        return evaluate(input)
    except Exception:
        return unreadable("the response could not be processed")


def evaluate(input):
    refusal = refusal_envelope(input)
    raw = parse_json(input)
    data, validation = extract_input(raw)
    if refusal is None:
        refusal = refusal_envelope(data)
    if not isinstance(validation, dict):
        validation = None  # create_response substitutes its default
    if refusal is not None:
        # Duo's 403 / 40301 refusal and any other handed-over vendor error are not data: report them as
        # Unevaluated (the permission named for 40301 only), never judge on them.
        return refusal_unevaluated(refusal, validation)
    if validation is not None and validation.get("status") == "failed":
        return unreadable("input validation failed; the body is not evidence", validation)
    items = response_items(data)
    if items is None or error_marked(data) or error_marked(raw):
        return unreadable("the body holds no \"response\" list, or is marked as an error", validation)
    if not items and not success_proven(raw):
        return unreadable("an empty list without Duo's own OK envelope is what a failed read defaults to", validation)
    if items and not any(isinstance(x, dict) for x in items):
        return unreadable("the list holds no object", validation)
    return measure(data, validation, items)


def measure(data, validation, codes):
    if isinstance(data, dict):
        stat = data.get("stat")
        metadata = data.get("metadata")
        total_objects = metadata.get("total_objects") if isinstance(metadata, dict) else None
    else:
        stat = "OK"
        total_objects = len(data)

    has_access = True
    bypass_code_count = len(codes)

    pass_reasons = [
        f"Duo Admin API endpoint /admin/v1/users/{{user_id}}/bypass_codes responded with stat='{stat}' "
        f"and a 'response' array (bypass_code_count={bypass_code_count}, total_objects={total_objects}), "
        f"demonstrating that emergency access (bypass) code data is reachable via the API."
    ]

    result = {
        "hasEmergencyAccessCodeAPIAccess": has_access,
        "bypassCodeCount": bypass_code_count,
    }

    input_summary = {
        "stat": stat,
        "bypassCodeCount": bypass_code_count,
        "totalObjectsReported": total_objects,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        input_summary=input_summary,
        metadata=META,
    )
