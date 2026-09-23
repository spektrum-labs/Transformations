
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
        configs = data
    elif isinstance(data, dict):
        configs = data.get("data") or data.get("results") or []
        if not isinstance(configs, list):
            configs = []
    else:
        configs = []

    org_configs = [c for c in configs if isinstance(c, dict) and c.get("target_type") == "organization"]
    enforced_org_configs = [c for c in org_configs if c.get("enforcement") == "enforced"]

    scope_configs = enforced_org_configs if enforced_org_configs else org_configs

    is_enabled = False
    matched_config_names = []
    for c in scope_configs:
        if c.get("advanced_security") == "enabled":
            is_enabled = True
            matched_config_names.append(c.get("name") or str(c.get("id")))

    total_configs = len(configs)
    total_org_configs = len(org_configs)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        names = ", ".join(matched_config_names) if matched_config_names else "an organization configuration"
        pass_reasons.append(
            f"Organization-level code security configuration(s) [{names}] have advanced_security='enabled' "
            f"(evaluated {total_org_configs} organization-scoped configuration(s) out of {total_configs} total)."
        )
    else:
        if total_org_configs == 0:
            fail_reasons.append(
                f"No organization-scoped (target_type='organization') code security configuration was found "
                f"among {total_configs} configuration(s) returned by the org."
            )
            recommendations.append(
                "Create and enforce an organization-level code security configuration with GitHub Advanced Security enabled."
            )
        else:
            statuses = [c.get("advanced_security") for c in scope_configs]
            fail_reasons.append(
                f"Organization-scoped configuration(s) report advanced_security statuses {statuses}, "
                f"none of which are 'enabled' (checked {len(scope_configs)} config(s))."
            )
            recommendations.append(
                "Enable GitHub Advanced Security in the organization's enforced code security configuration."
            )

    result = {
        "isAdvancedSecurityEnabled": is_enabled,
        "totalConfigurations": total_configs,
        "organizationScopedConfigurations": total_org_configs,
    }

    input_summary = {
        "totalConfigurations": total_configs,
        "organizationScopedConfigurations": total_org_configs,
        "enforcedOrganizationConfigurations": len(enforced_org_configs),
    }

    metadata = {
        "transformationId": "isAdvancedSecurityEnabled",
        "vendor": "GitHub",
        "category": "devsecops",
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
