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

    if isinstance(data, list):
        policies = data
        meta = {}
    elif isinstance(data, dict):
        policies = data.get("resources") or []
        if not isinstance(policies, list):
            policies = []
        meta = data.get("meta") or {}
    else:
        policies = []
        meta = {}

    pagination = meta.get("pagination") or {}
    total_reported = pagination.get("total")

    total_policies = len(policies)
    enabled_count = 0
    enabled_with_group_count = 0
    sample_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        is_enabled = bool(p.get("enabled"))
        groups = p.get("groups") or []
        has_groups = isinstance(groups, list) and len(groups) > 0
        if is_enabled:
            enabled_count = enabled_count + 1
            if has_groups:
                enabled_with_group_count = enabled_with_group_count + 1
                if len(sample_names) < 5:
                    sample_names.append(p.get("name") or p.get("id") or "unknown")

    is_patch_mgmt_enabled = enabled_with_group_count > 0

    input_summary = {
        "totalSensorUpdatePolicies": total_policies,
        "reportedTotal": total_reported,
        "enabledPolicies": enabled_count,
        "enabledPoliciesWithGroupAssignment": enabled_with_group_count,
    }

    if is_patch_mgmt_enabled:
        pass_reasons = [
            f"Found {enabled_with_group_count} enabled Sensor Update Policy(ies) assigned to at least one host group out of {total_policies} sampled policies (e.g. {', '.join(sample_names)}). This governs sensor build updates rather than leaving them to manual installer choice."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No enabled Sensor Update Policy with a host group assignment was found among {total_policies} policies retrieved (enabled_count={enabled_count})."
        ]
        recommendations = [
            "Enable at least one Sensor Update Policy and assign it to the relevant host group(s) so sensor build updates are governed rather than manually installed."
        ]

    result = {
        "isPatchManagementEnabled": is_patch_mgmt_enabled,
        "totalSensorUpdatePolicies": total_policies,
        "enabledPoliciesWithGroupAssignment": enabled_with_group_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
