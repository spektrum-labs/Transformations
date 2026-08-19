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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_section = data.get("api") or {}
    api_enabled = api_section.get("enabled")

    org_id = data.get("id") or "unknown"
    org_name = data.get("name") or "unknown organization"

    if api_enabled is True:
        result = {"isProgrammaticAccessEnabled": True}
        pass_reasons = [
            f"Organization '{org_name}' (id={org_id}) has api.enabled=true, "
            "confirming Dashboard API access is enabled at the organization level."
        ]
        fail_reasons = []
        recommendations = []
    elif api_enabled is False:
        result = {"isProgrammaticAccessEnabled": False}
        pass_reasons = []
        fail_reasons = [
            f"Organization '{org_name}' (id={org_id}) has api.enabled=false, "
            "meaning Dashboard API access is disabled at the organization level."
        ]
        recommendations = [
            "Enable Dashboard API access for the organization in Organization > Settings "
            "to allow programmatic control of the firewall fleet."
        ]
    else:
        result = {"isProgrammaticAccessEnabled": False}
        pass_reasons = []
        fail_reasons = [
            f"Organization '{org_name}' (id={org_id}) response did not contain an api.enabled field; "
            "cannot confirm Dashboard API access is enabled."
        ]
        recommendations = [
            "Verify organization API access configuration via the Meraki dashboard or API."
        ]

    input_summary = {"organizationId": org_id, "apiEnabled": api_enabled}

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isProgrammaticAccessEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
