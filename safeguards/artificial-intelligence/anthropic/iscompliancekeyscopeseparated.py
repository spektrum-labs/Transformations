"""
Transformation: isComplianceKeyScopeSeparated
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude Compliance API
Evaluates: No active Compliance Access Key can both read and delete user content.
Anthropic's guidance is that a workflow which reads and deletes uses two keys with
separate scopes, so a leaked read key cannot delete data.
API Source: getComplianceAccessKeys (the api_keys list of
GET /v1/compliance/organizations/{uuid}/settings; key secrets are never returned)
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    # Decode a JSON string or bytes BEFORE inspecting shape, so str, bytes and dict
    # inputs are read the same way. A string that is not JSON raises into transform()'s
    # handler, which reports the criterion as not evaluated.
    if isinstance(input_data, (str, bytes)):
        if isinstance(input_data, bytes):
            input_data = input_data.decode("utf-8")
        input_data = json.loads(input_data)
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
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


METADATA = {
    "transformationId": "isComplianceKeyScopeSeparated",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}

# Unique sentinel. object() is unavailable in the RestrictedPython sandbox
# Token-Service runs transforms in, so a fresh list is used instead: a list
# literal is never interned, which keeps the "is MISSING" identity checks valid.
MISSING = ["__missing__"]

# ANSWER CONTRACT. True only when the vendor data was read and shows the control.
# False only when the vendor data was read and shows the control is absent.
# None in every other case (refused call, empty or unreadable body, missing row,
# exception). Each None path also sets dataCollection.status to "error" (through
# api_errors), which Token-Service reports as not evaluated rather than failed:
# nothing was looked at, so nothing is claimed either way.
UNKNOWN = None

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN.
# Anthropic's Compliance API takes a Compliance Access Key (sk-ant-api01-...) created
# in claude.ai > Organization settings > API. The organization and settings endpoints
# need the read:compliance_org_data scope; the Activity Feed needs
# read:compliance_activities. Scopes are fixed when a key is created.
REFUSAL_REASONS = {
    400: ("the vendor rejected the request",
          "If the message says the Compliance API is not enabled, the primary owner enables it "
          "at claude.ai > Organization settings > API."),
    401: ("the credential was rejected",
          "Confirm the Compliance Access Key has not been deleted. Deleting a key takes effect "
          "on the next request."),
    403: ("the credential is not permitted to call the endpoint",
          "Create a Compliance Access Key in claude.ai > Organization settings > API with the "
          "read:compliance_org_data and read:compliance_activities scopes. Scopes cannot be "
          "added to an existing key. An Admin API key (sk-ant-admin01-...) reaches the Activity "
          "Feed only and returns 403 on the settings endpoint."),
    404: ("the endpoint or organization was not found",
          "Check the Organization ID: it is the uuid returned by GET /v1/compliance/organizations, "
          "and it must be a linked organization, not the parent organization. If every request "
          "returns 404, the settings endpoint is not yet enabled for this parent organization."),
    429: ("the vendor rate-limited the call",
          "The Compliance API allows 600 requests per minute per parent organization. Retry."),
}


def detect_refusal(data):
    """Return (status, why, fix) when the payload is an error envelope, else None.

    Two envelope shapes reach a transform: the generic one (error / errorType /
    status == "Error" with statusCode) and Integration-Service's vendor relay
    ({"integrationName", "errorMessage", "vendorStatus", "vendorError", ...}).
    """
    if not isinstance(data, dict):
        return None
    relay_status = data.get("vendorStatus")
    is_relay = "errorMessage" in data or relay_status is not None
    is_generic = bool(data.get("error") or data.get("errorType") or data.get("status") == "Error")
    if not (is_relay or is_generic):
        return None
    status = relay_status if relay_status is not None else (data.get("statusCode") or data.get("status_code"))
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = None
    why, fix = REFUSAL_REASONS.get(status, (
        "the vendor call did not succeed",
        "Inspect the integration method response for the underlying error."))
    detail = data.get("errorMessage") or data.get("message") or ""
    if not detail and isinstance(data.get("error"), dict):
        detail = data["error"].get("message") or ""
    if detail:
        why = why + " (" + str(detail) + ")"
    return status, why, fix


NOT_ENABLED_TEXT = "compliance api is not enabled"


def api_not_enabled(data):
    """True when the vendor answered 400 "Compliance API is not enabled for this organization".

    Anthropic returns that body on every Compliance API endpoint until the primary owner
    enables the API, and again after an administrator turns it off. Unlike a 401, 403 or
    404 it is a statement about the organization, not about Spektrum's credential.
    """
    if not isinstance(data, dict):
        return False
    status = data.get("vendorStatus")
    if status is None:
        status = data.get("statusCode") or data.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        return False
    if status != 400:
        return False
    parts = [data.get("errorMessage"), data.get("message"), data.get("vendorError"), data.get("error")]
    text = " ".join([json.dumps(p) if isinstance(p, (dict, list)) else str(p or "") for p in parts]).lower()
    return NOT_ENABLED_TEXT in text


def unknown_response(validation, reason, recommendation, input_summary):
    """Not evaluated: the value is None and dataCollection.status is "error"."""
    return create_response(
        result={"isComplianceKeyScopeSeparated": UNKNOWN, "evaluable": False},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation],
        input_summary=input_summary,
        metadata=METADATA,
        api_errors=[reason],
    )


def refusal_response(validation, data, what):
    refusal = detect_refusal(data)
    if not refusal:
        return None
    status, why, fix = refusal
    return unknown_response(
        validation,
        "The " + what + " could not be read because " + why +
        ". This is a connectivity or credential-scope result, not a finding about the "
        "organization, so the control is not evaluated.",
        fix,
        {"endpointReachable": False, "httpStatus": status},
    )


DELETE_SCOPE = "delete:compliance_user_data"
CONTENT_READ_SCOPE = "read:compliance_user_data"


def key_items(data):
    """The api_keys entries as a list, or None when the body holds no list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "api_keys", "apiKeys", "complianceApiKeys"):
            if isinstance(data.get(key), list):
                return data[key]
    return None


def evaluate(input):
    data, validation = extract_input(input)
    refused = refusal_response(validation, data, "Compliance Access Key list")
    if refused:
        return refused

    keys = key_items(data)
    if not keys:
        return unknown_response(
            validation,
            "The settings response listed no Compliance Access Keys. The key Spektrum uses is "
            "always listed, so an empty list means the key inventory was not read.",
            "Confirm the Compliance Access Key carries read:compliance_org_data and re-run the evaluation.",
            {"keysReported": 0},
        )

    active = [k for k in keys if isinstance(k, dict) and k.get("is_active") is True]
    inactive_count = len([k for k in keys if isinstance(k, dict) and k.get("is_active") is False])
    if not active:
        return unknown_response(
            validation,
            "No key in the list is marked active, yet the key Spektrum used to read it must be "
            "active, so the key inventory is not trusted.",
            "Report this to the Spektrum integrations team with the raw API response.",
            {"keysReported": len(keys), "activeKeys": 0},
        )

    combined = []
    unreadable = 0
    content_readers = 0
    for k in active:
        scopes = k.get("scopes")
        if not isinstance(scopes, list):
            unreadable = unreadable + 1
            continue
        scope_set = [str(s) for s in scopes]
        if CONTENT_READ_SCOPE in scope_set:
            content_readers = content_readers + 1
        reads = [s for s in scope_set if s.startswith("read:")]
        if DELETE_SCOPE in scope_set and reads:
            combined.append(str(k.get("name") or k.get("id") or "unnamed key"))

    summary = {"keysReported": len(keys), "activeKeys": len(active), "inactiveKeys": inactive_count,
               "keysReadingAndDeleting": len(combined), "keysWithUnreadableScopes": unreadable,
               "keysReadingUserContent": content_readers}
    findings = []
    if content_readers:
        findings.append(
            str(content_readers) + " active key(s) carry " + CONTENT_READ_SCOPE + ", which reads "
            "every chat, file, project and session transcript in the organizations the key covers."
        )
    if inactive_count:
        findings.append(str(inactive_count) + " deactivated key(s) are listed; they cannot authenticate.")

    if combined:
        return create_response(
            result={"isComplianceKeyScopeSeparated": False, "evaluable": True},
            validation=validation,
            fail_reasons=[
                str(len(combined)) + " active Compliance Access Key(s) can both read and delete "
                "user content: " + ", ".join(combined[:10]) + ". A leak of one of these keys "
                "exposes content and allows its permanent deletion."
            ],
            recommendations=[
                "Replace each of these keys with two keys: one with the read scopes and one with " +
                DELETE_SCOPE + " only. Scopes cannot be changed on an existing key."
            ],
            input_summary=summary,
            additional_findings=findings,
            metadata=METADATA,
        )
    if unreadable:
        return unknown_response(
            validation,
            str(unreadable) + " active key(s) had no readable scope list, so read/delete "
            "separation is not proven.",
            "Report this to the Spektrum integrations team with the raw API response.",
            summary,
        )
    return create_response(
        result={"isComplianceKeyScopeSeparated": True, "evaluable": True},
        validation=validation,
        pass_reasons=[
            "All " + str(len(active)) + " active Compliance Access Key(s) were read and none holds "
            "both a read scope and " + DELETE_SCOPE + "."
        ],
        input_summary=summary,
        additional_findings=findings,
        metadata=METADATA,
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        message = "Transformation raised an unexpected error, so the control is not evaluated: " + str(exc)
        return create_response(
            result={"isComplianceKeyScopeSeparated": UNKNOWN, "evaluable": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            api_errors=[message],
            fail_reasons=[message],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
