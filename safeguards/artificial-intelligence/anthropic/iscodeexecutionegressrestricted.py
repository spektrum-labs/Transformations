"""
Transformation: isCodeExecutionEgressRestricted
Vendor: Anthropic  |  Category: Artificial Intelligence
Evaluates: Ensures the code execution sandbox cannot reach the network, preventing data egress from executed code.
API Source: getEffectiveOrganizationSettings
"""
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
    "transformationId": "isCodeExecutionEgressRestricted",
    "vendor": "Anthropic",
    "category": "Artificial Intelligence",
}


_MISSING = object()


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "enabled", "on")
    return bool(value)


def _settings_map(data):
    """Reduce the effective-settings rows to {name: value}.

    A setting this organization's administrators cannot change is omitted from
    the response entirely, so a missing name means "not controllable here",
    never "off". Callers must distinguish absent from False, which is why this
    returns a plain dict and callers use the _MISSING sentinel.
    """
    rows = None
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        for key in ("data", "settings"):
            if isinstance(data.get(key), list):
                rows = data[key]
                break
    if rows is None:
        rows = []
    out = {}
    for row in rows:
        if isinstance(row, dict) and row.get("name") is not None:
            out[row["name"]] = row.get("value", _MISSING)
    return out


def _evaluate(input):
    data, validation = extract_input(input)
    # Token-Service navigates into the response's "data" key (codeexecutor
    # navigation_keys), so this transform usually receives the bare navigated
    # value. Accept that, the returnSpec-mapped dict, and the raw API body so
    # the same file works in the live pipeline and in direct/local testing.
    settings = _settings_map(data)
    settings_count = len(settings)
    egress_raw = settings.get("code_execution_network_egress_enabled", _MISSING)
    exec_raw = settings.get("code_execution_enabled", _MISSING)

    if egress_raw is _MISSING:
        return create_response(
            result={"isCodeExecutionEgressRestricted": False, "codeExecutionEnabled": None,
                    "networkEgressEnabled": None},
            validation=validation,
            fail_reasons=[
                "The effective organization settings response did not include a "
                "'code_execution_network_egress_enabled' row, so sandbox egress restriction "
                "cannot be proven."
            ],
            recommendations=["Confirm the organization's plan exposes the code execution controls."],
            input_summary={"settingsReported": settings_count, "settingPresent": False},
            metadata=METADATA,
        )

    egress_on = _as_bool(egress_raw)
    exec_on = None if exec_raw is _MISSING else _as_bool(exec_raw)
    result = not egress_on

    findings = []
    if exec_on is False:
        findings.append(
            "Code execution is disabled for this organization. Anthropic reports "
            "code_execution_network_egress_enabled as false whenever code execution is off, so "
            "this pass reflects an unused capability rather than a hardened sandbox."
        )
    elif exec_on is None:
        findings.append("code_execution_enabled was not reported, so the pass cannot be attributed to a hardened sandbox versus an unused capability.")

    if result:
        pass_reasons = [
            "Code execution network egress is disabled, so code run in the sandbox cannot reach "
            "the network."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Code execution network egress is enabled, so code run in the sandbox can make "
            "outbound network requests and exfiltrate data."
        ]
        recommendations = ["Disable network egress for code execution in claude.ai > Organization settings."]

    return create_response(
        result={
            "isCodeExecutionEgressRestricted": result,
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
        return _evaluate(input)
    except Exception as exc:  # never raise into the pipeline
        return create_response(
            result={"isCodeExecutionEgressRestricted": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(exc)],
            fail_reasons=["Transformation raised an unexpected error: " + str(exc)],
            recommendations=["Report this to the Spektrum integrations team with the raw API response."],
            metadata=METADATA,
        )
