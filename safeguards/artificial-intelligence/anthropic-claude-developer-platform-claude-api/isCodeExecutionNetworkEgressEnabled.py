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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    settings_list = []
    if isinstance(data, dict):
        settings_list = data.get("settings") or []
    elif isinstance(data, list):
        settings_list = data

    if not isinstance(settings_list, list):
        settings_list = []

    egress_row = None
    code_exec_row = None
    for row in settings_list:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if name == "code_execution_network_egress_enabled":
            egress_row = row
        elif name == "code_execution_enabled":
            code_exec_row = row

    input_summary = {
        "totalSettingsRows": len(settings_list),
        "codeExecutionEnabledRow": code_exec_row,
        "codeExecutionNetworkEgressRow": egress_row,
    }

    transformation_errors = []
    if egress_row is None:
        transformation_errors.append(
            "code_execution_network_egress_enabled row not found in settings array"
        )

    egress_value = egress_row.get("value") if egress_row is not None else None
    code_exec_enabled = code_exec_row.get("value") if code_exec_row is not None else None

    # The criterion "Code-Execution Network Egress Controlled" is satisfied when
    # the vendor's own setting row reports network egress for code execution is
    # NOT open (value is explicitly False), meaning outbound connections are
    # restricted to the approved domain allowlist rather than open internet access.
    is_controlled = (egress_row is not None) and (egress_value == False)

    result = {
        "isCodeExecutionNetworkEgressEnabled": is_controlled,
        "codeExecutionNetworkEgressRawValue": egress_value,
        "codeExecutionEnabled": code_exec_enabled,
    }

    if egress_row is None:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                "No 'code_execution_network_egress_enabled' setting row was present in the "
                "organization's effective settings response, so egress control status could not be confirmed."
            ],
            recommendations=[
                "Verify the compliance organization settings endpoint returns the "
                "code_execution_network_egress_enabled row, or confirm this setting via the admin console."
            ],
            input_summary=input_summary,
            transformation_errors=transformation_errors,
            metadata={
                "transformationId": "isCodeExecutionNetworkEgressEnabled",
                "vendor": "Anthropic Claude Developer Platform Claude API",
                "category": "artificial-intelligence",
            },
        )

    if is_controlled:
        pass_reasons = [
            f"Effective organization settings row 'code_execution_network_egress_enabled' has value={egress_value}, "
            f"indicating open network egress for code execution is disabled and outbound connections are restricted "
            f"to the approved domain allowlist. code_execution_enabled={code_exec_enabled}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Effective organization settings row 'code_execution_network_egress_enabled' has value={egress_value}, "
            f"indicating code execution is permitted open network egress instead of being restricted to an "
            f"approved domain allowlist. code_execution_enabled={code_exec_enabled}."
        ]
        recommendations = [
            "Disable code_execution_network_egress_enabled (or configure the org's code-execution "
            "network allowlist) so that code run by Claude Code is restricted to approved domains rather "
            "than open internet access."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isCodeExecutionNetworkEgressEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
