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

    policies = data.get("resources") or []
    if not isinstance(policies, list):
        policies = []

    total_policies = len(policies)
    enabled_policies = []
    disabled_policies = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        if p.get("enabled"):
            enabled_policies.append(p)
        else:
            disabled_policies.append(p)

    enabled_count = len(enabled_policies)
    is_enabled = enabled_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_policies == 0:
        fail_reasons.append(
            "No prevention policies were returned by getCombinedPreventionPolicies; "
            "cannot confirm EDR/prevention capability is enabled for any host."
        )
        recommendations.append(
            "Create and assign at least one Falcon prevention policy with enabled=true "
            "to hosts in this CID."
        )
    elif is_enabled:
        sample_names = [p.get("name") for p in enabled_policies[:5] if p.get("name")]
        pass_reasons.append(
            f"{enabled_count} of {total_policies} prevention policies report enabled=true "
            f"(e.g. {', '.join([str(n) for n in sample_names])})."
        )
    else:
        fail_reasons.append(
            f"All {total_policies} prevention policies returned have enabled=false; "
            "Falcon prevention/EDR capability is not active for hosts assigned to these policies."
        )
        recommendations.append(
            "Enable the relevant Falcon prevention policy (set enabled=true) for the "
            "policy assigned to production host groups."
        )

    result = {
        "isEDREnabled": is_enabled,
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_count,
    }

    input_summary = {
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_count,
        "disabledPolicies": len(disabled_policies),
    }

    metadata = {
        "transformationId": "isEDREnabled",
        "vendor": "Crowdstrike",
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
