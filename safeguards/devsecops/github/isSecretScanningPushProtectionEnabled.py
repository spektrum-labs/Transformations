"""Transformation: isSecretScanningPushProtectionEnabled"""
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
        configs = data
    elif isinstance(data, dict):
        configs = data.get("data") or data.get("configurations") or []
        if not isinstance(configs, list):
            configs = []
    else:
        configs = []

    org_configs = [c for c in configs if isinstance(c, dict) and c.get("target_type") == "organization"]

    enabled_enforced = [
        c for c in org_configs
        if c.get("secret_scanning_push_protection") == "enabled" and c.get("enforcement") == "enforced"
    ]
    enabled_any = [
        c for c in org_configs
        if c.get("secret_scanning_push_protection") == "enabled"
    ]

    is_enabled = len(enabled_enforced) > 0

    total_org_configs = len(org_configs)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        names = [c.get("name") for c in enabled_enforced]
        pass_reasons.append(
            f"Organization-level code security configuration(s) {names} have "
            f"secret_scanning_push_protection='enabled' and enforcement='enforced' "
            f"out of {total_org_configs} organization-scoped configuration(s)."
        )
    else:
        if total_org_configs == 0:
            fail_reasons.append(
                "No organization-scoped code security configuration was found in the "
                "listOrgCodeSecurityConfigurations response; cannot confirm push protection policy."
            )
            recommendations.append(
                "Create an organization-level code security configuration enforcing secret scanning push protection."
            )
        elif enabled_any:
            names = [c.get("name") for c in enabled_any]
            fail_reasons.append(
                f"Organization configuration(s) {names} have secret_scanning_push_protection='enabled' "
                f"but enforcement is not 'enforced' (actual enforcement values: "
                f"{[c.get('enforcement') for c in enabled_any]})."
            )
            recommendations.append(
                "Set the enforcement status of the organization security configuration to 'enforced' "
                "so push protection applies to all repositories."
            )
        else:
            values = [c.get("secret_scanning_push_protection") for c in org_configs]
            fail_reasons.append(
                f"None of the {total_org_configs} organization-scoped configuration(s) have "
                f"secret_scanning_push_protection='enabled' (observed values: {values})."
            )
            recommendations.append(
                "Enable secret scanning push protection in the organization's code security configuration "
                "and enforce it across all repositories."
            )

    result = {
        "isSecretScanningPushProtectionEnabled": is_enabled,
        "organizationConfigCount": total_org_configs,
        "enabledEnforcedConfigCount": len(enabled_enforced),
    }

    input_summary = {
        "totalConfigurations": len(configs) if isinstance(configs, list) else 0,
        "organizationScopedConfigurations": total_org_configs,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSecretScanningPushProtectionEnabled",
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
