"""
Transformation: isCodeExecutionNetworkEgressEnabled
Vendor: Anthropic  |  Category: Artificial Intelligence
Product: Claude
Evaluates: Ensures the code execution sandbox cannot reach the network, preventing data egress from executed code.
API Source: getEffectiveOrganizationSettings
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    # Decode a JSON string or bytes BEFORE inspecting shape. Without this a str body
    # matches no branch here, stays a str, and every caller's `isinstance(data, dict)`
    # test fails -- so a perfectly good response is read as "nothing came back" and the
    # criterion is answered from an empty shape. CLAUDE.md's `_parse_input` pattern makes
    # str, bytes and dict equivalent everywhere else in this repo; this family did not.
    # A string that is not JSON raises into each transform's existing handler: fail closed.
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
    "transformationId": "isCodeExecutionNetworkEgressEnabled",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


# Unique sentinel. object() is unavailable in the RestrictedPython sandbox
# Token-Service runs transforms in, so a fresh list is used instead: a list
# literal is never interned, which keeps the "is MISSING" identity checks valid.
MISSING = ["__missing__"]

# HTTP status -> why the call was refused. These are NOT posture findings: they mean
# the credential or tenancy cannot reach the endpoint, so the control is UNKNOWN
# rather than absent. Anthropic's compliance org-data endpoints (settings, groups,
# organizations, users) accept only a Compliance Access Key (sk-ant-api01-...)
# created in claude.ai; an Admin API key (sk-ant-admin01-...) gets 403, and a
# standalone Claude Console organization can reach the Activity Feed only.
REFUSAL_REASONS = {
    401: ("the credential was rejected",
          "Confirm the key is an admin-class key and has not been revoked or expired."),
    403: ("this organization's credential is not permitted to call the endpoint",
          "This endpoint requires a Compliance Access Key (sk-ant-api01-...) created in "
          "claude.ai > Organization settings > API with the read:org_audit scope. An Admin "
          "API key (sk-ant-admin01-...) from Claude Console returns 403 here. A standalone "
          "Claude Console organization cannot read these settings at all - treat this "
          "criterion as not applicable for that tenant rather than failed."),
    404: ("the endpoint or organization was not found",
          "Check the Organization ID. The compliance endpoints take a compliance "
          "organization uuid from GET /v1/compliance/organizations, which is a different "
          "value from the Console organization id shown at "
          "platform.claude.com/settings/organization."),
    429: ("the vendor rate-limited the call",
          "Compliance endpoints allow 600 requests/minute per parent organization. Retry."),
}



# FAIL-CLOSED CONTRACT. The requirement token asks isEquals **false** (inherited
# requirementsUid fcf72fbc-..., "Code Execution Network Egress Restricted"), so this
# criterion reports the RAW setting and False is the COMPLIANT answer. That makes the
# usual "return False when unsure" fallback a false pass here: it satisfies the
# requirement whenever nothing could be read. So:
#   - False  only when the settings row was read and its value is literally false;
#   - True   when the row was read and egress is on;
#   - None   in every other case (refused call, no settings, missing row, unreadable
#            value, exception). None never equals false in Token-Service's isEquals
#            comparison, so it cannot satisfy the requirement.
# A refused call or an empty settings response also sets dataCollection.status to
# "error" (via api_errors), which Token-Service reads as "not evaluated" (grey) rather
# than a measured failure: nothing was looked at.
UNKNOWN = None

TRUE_WORDS = ("true", "enabled", "on")
FALSE_WORDS = ("false", "disabled", "off")


def detect_refusal(data):
    """Return (status, why, fix) when the payload is an error envelope, else None.

    Two envelope shapes reach a transform: the generic one (error / errorType /
    status=="Error" with statusCode) and Integration-Service's vendor relay
    ({"integrationName", "errorMessage", "vendorStatus": 401, "vendorError", ...}),
    which is what /integration/run returned for this definition on 2026-09-25.
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


def strict_bool(value):
    """True / False for an unambiguous boolean, else None.

    The old reader used bool(value), so a null value or an unrecognised string read
    as False, which is the compliant answer for this criterion.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        word = value.strip().lower()
        if word in TRUE_WORDS:
            return True
        if word in FALSE_WORDS:
            return False
    return None


def settings_rows(data):
    """The effective-settings rows as a list, or None when the body has no rows list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "settings"):
            if isinstance(data.get(key), list):
                return data[key]
    return None


def settings_map(rows):
    """Reduce the effective-settings rows to {name: value}.

    A setting this organization's administrators cannot change is omitted from
    the response entirely, so a missing name means "not controllable here",
    never "off". Callers must distinguish absent from False, which is why
    callers use the MISSING sentinel.
    """
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name") is not None:
            out[row["name"]] = row.get("value", MISSING)
    return out


def unknown_response(validation, fail_reason, recommendation, input_summary,
                     api_errors=None, transformation_errors=None):
    return create_response(
        result={"isCodeExecutionNetworkEgressEnabled": UNKNOWN, "evaluable": False},
        validation=validation,
        fail_reasons=[fail_reason],
        recommendations=[recommendation],
        input_summary=input_summary,
        metadata=METADATA,
        api_errors=api_errors,
        transformation_errors=transformation_errors,
    )


def evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare settings list.
    # Accept that, the returnSpec-mapped dict, and the raw API body.
    refusal = detect_refusal(data)
    if refusal:
        refusal_status, refusal_why, refusal_fix = refusal
        message = ("The organization settings could not be read because " + refusal_why +
                   ". The control's real state is unknown, so egress restriction is not proven.")
        return unknown_response(
            validation, message, refusal_fix,
            {"endpointReachable": False, "httpStatus": refusal_status},
            api_errors=[message],
        )

    rows = settings_rows(data)
    if not rows:
        message = ("The effective organization settings response contained no settings rows, "
                   "so nothing about code execution egress was read.")
        return unknown_response(
            validation, message,
            "Confirm the Compliance Access Key and Organization ID, then re-run the evaluation.",
            {"settingsReported": 0},
            api_errors=[message],
        )

    settings = settings_map(rows)
    settings_count = len(settings)
    egress_raw = settings.get("code_execution_network_egress_enabled", MISSING)
    exec_raw = settings.get("code_execution_enabled", MISSING)

    if egress_raw is MISSING:
        return unknown_response(
            validation,
            "The effective organization settings did not include a "
            "'code_execution_network_egress_enabled' row. Anthropic omits a setting the "
            "organization cannot control, so a missing row means 'not controllable here', "
            "not 'off'. Sandbox egress restriction is not proven.",
            "Confirm the organization's plan exposes the code execution controls, or attest this control manually.",
            {"settingsReported": settings_count, "settingPresent": False},
        )

    egress_on = strict_bool(egress_raw)
    if egress_on is None:
        return unknown_response(
            validation,
            "The 'code_execution_network_egress_enabled' row has a value that is not a "
            "boolean (" + repr(egress_raw) + "), so sandbox egress restriction is not proven.",
            "Report this to the Spektrum integrations team with the raw API response.",
            {"settingsReported": settings_count, "settingPresent": True, "valueReadable": False},
        )

    exec_on = None if exec_raw is MISSING else strict_bool(exec_raw)

    findings = []
    if exec_on is False:
        findings.append(
            "Code execution is disabled for this organization. Anthropic reports "
            "code_execution_network_egress_enabled as false whenever code execution is off, so "
            "this pass reflects an unused capability rather than a hardened sandbox."
        )
    elif exec_on is None:
        findings.append("code_execution_enabled was not reported, so a pass cannot be attributed to a hardened sandbox versus an unused capability.")

    if egress_on:
        pass_reasons = []
        fail_reasons = [
            "Code execution network egress is enabled, so code run in the sandbox can make "
            "outbound network requests and exfiltrate data."
        ]
        recommendations = ["Disable network egress for code execution in claude.ai > Organization settings."]
    else:
        pass_reasons = [
            "The 'code_execution_network_egress_enabled' setting was read and is false, so code "
            "run in the sandbox cannot reach the network."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={
            "isCodeExecutionNetworkEgressEnabled": egress_on,
            "evaluable": True,
            "codeExecutionEnabled": exec_on,
            "networkEgressEnabled": egress_on,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=findings,
        input_summary={"settingsReported": settings_count, "networkEgressEnabled": egress_on},
        metadata=METADATA,
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isCodeExecutionNetworkEgressEnabled": UNKNOWN, "evaluable": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error, so egress restriction is not proven: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
