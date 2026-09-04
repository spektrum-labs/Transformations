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

    api_errors = []
    if data.get("error"):
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    policies = data.get("resources") or []
    if not isinstance(policies, list):
        policies = []

    total_policies = len(policies)
    enabled_assigned_policies = []
    enabled_unassigned_policies = []
    disabled_policies = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        is_enabled = bool(p.get("enabled"))
        groups = p.get("groups") or []
        has_groups = isinstance(groups, list) and len(groups) > 0
        name = p.get("name") or p.get("id") or "unnamed policy"
        if is_enabled and has_groups:
            enabled_assigned_policies.append(name)
        elif is_enabled and not has_groups:
            enabled_unassigned_policies.append(name)
        elif not is_enabled:
            disabled_policies.append(name)

    is_enabled_result = len(enabled_assigned_policies) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    input_summary = {
        "totalPolicies": total_policies,
        "enabledAssignedCount": len(enabled_assigned_policies),
        "enabledUnassignedCount": len(enabled_unassigned_policies),
        "disabledCount": len(disabled_policies),
    }

    if api_errors:
        fail_reasons.append(
            f"Sensor update policy API returned an error: {api_errors[0]}"
        )
        recommendations.append(
            "Verify CrowdStrike API credentials and scopes for the sensor-update-policies collection, then retry."
        )
    elif total_policies == 0:
        fail_reasons.append(
            "No sensor update policies were returned by getCombinedSensorUpdatePolicies; no policy is assigned to any host group."
        )
        recommendations.append(
            "Create and assign a Sensor Update Policy to host groups in the Falcon console to govern sensor build updates."
        )
    elif is_enabled_result:
        sample = ", ".join(enabled_assigned_policies[:5])
        pass_reasons.append(
            f"{len(enabled_assigned_policies)} of {total_policies} sensor update policies are enabled and assigned to host groups (e.g. {sample}), confirming sensor build updates are governed rather than left to manual installer choice."
        )
    else:
        fail_reasons.append(
            f"None of the {total_policies} sensor update policies found are both enabled=true and assigned to a host group (enabled-but-unassigned: {len(enabled_unassigned_policies)}, disabled: {len(disabled_policies)})."
        )
        recommendations.append(
            "Enable the Sensor Update Policy and assign it to the relevant host groups so sensor build updates are governed."
        )

    result = {
        "isPatchManagementEnabled": is_enabled_result,
        "totalPolicies": total_policies,
        "enabledAssignedPolicies": len(enabled_assigned_policies),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
