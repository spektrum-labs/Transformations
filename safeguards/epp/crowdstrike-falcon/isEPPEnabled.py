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
    assigned_policies = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        groups = p.get("groups") or []
        if isinstance(groups, list) and len(groups) > 0:
            assigned_policies.append(p)

    enabled_assigned = [p for p in assigned_policies if p.get("enabled") is True]
    disabled_assigned = [p for p in assigned_policies if p.get("enabled") is not True]

    total_assigned = len(assigned_policies)
    total_enabled_assigned = len(enabled_assigned)

    is_epp_enabled = total_assigned > 0 and total_enabled_assigned == total_assigned

    input_summary = {
        "totalPolicies": total_policies,
        "assignedPolicies": total_assigned,
        "enabledAssignedPolicies": total_enabled_assigned,
        "disabledAssignedPolicies": len(disabled_assigned),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_assigned == 0:
        fail_reasons.append(
            "No prevention policies with host-group assignments were found among %d total policies; cannot confirm enforcement." % total_policies
        )
        recommendations.append(
            "Assign at least one prevention policy to a host group and ensure its top-level 'enabled' flag is set to true."
        )
    elif is_epp_enabled:
        names = ", ".join([str(p.get("name")) for p in enabled_assigned][:5])
        pass_reasons.append(
            "All %d host-group-assigned prevention policies have enabled=true (e.g. %s)." % (total_enabled_assigned, names)
        )
    else:
        names = ", ".join([str(p.get("name")) for p in disabled_assigned][:5])
        fail_reasons.append(
            "%d of %d host-group-assigned prevention policies have enabled=false (e.g. %s), meaning prevention is defined but not actively enforced on those host groups." % (len(disabled_assigned), total_assigned, names)
        )
        recommendations.append(
            "Enable the top-level 'enabled' flag on all prevention policies assigned to host groups so prevention actions are actively enforced."
        )

    result = {
        "isEPPEnabled": is_epp_enabled,
        "totalAssignedPolicies": total_assigned,
        "enabledAssignedPolicies": total_enabled_assigned,
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
            "transformationId": "isEPPEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
