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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("resources") or data.get("data") or []
    else:
        policies = []

    if not isinstance(policies, list):
        policies = []

    total_policies = len(policies)
    enabled_policies = [p for p in policies if isinstance(p, dict) and p.get("enabled")]
    enabled_count = len(enabled_policies)

    covering_policies = []
    for p in enabled_policies:
        groups = p.get("groups") or []
        is_platform_default = p.get("name") == "platform_default"
        if groups or is_platform_default:
            covering_policies.append(p)

    covering_count = len(covering_policies)
    is_configured = covering_count > 0

    covering_names = [p.get("name") or p.get("id") or "unknown" for p in covering_policies][:10]
    covering_platforms = list({p.get("platform_name") for p in covering_policies if p.get("platform_name")})

    if is_configured:
        pass_reasons = [
            f"Found {covering_count} enabled prevention policy(ies) assigned to a host group or acting as platform_default "
            f"out of {total_policies} total prevention policies ({enabled_count} enabled). "
            f"Covering policies: {covering_names}, platforms covered: {covering_platforms}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No enabled prevention policy is assigned to a host group or configured as platform_default. "
            f"Total prevention policies observed: {total_policies}, enabled: {enabled_count}."
        ]
        recommendations = [
            "Create or enable a Prevention Policy in CrowdStrike Falcon and assign it to the host group(s) "
            "covering the endpoint population, or ensure the platform_default policy is enabled."
        ]

    result = {
        "isEPPConfigured": is_configured,
        "totalPreventionPolicies": total_policies,
        "enabledPreventionPolicies": enabled_count,
        "coveringPreventionPolicies": covering_count,
    }

    input_summary = {
        "totalPreventionPolicies": total_policies,
        "enabledPreventionPolicies": enabled_count,
        "coveringPreventionPolicies": covering_count,
    }

    metadata = {
        "transformationId": "isEPPConfigured",
        "vendor": "CrowdStrike Falcon",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
