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

    if isinstance(data, dict):
        policies = data.get("resources") or data.get("data") or []
    elif isinstance(data, list):
        policies = data
    else:
        policies = []

    if not isinstance(policies, list):
        policies = []

    critical_keywords = ["server", "critical", "production", "domain controller", "dc", "prod"]

    critical_policies = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        name = (p.get("name") or "").lower()
        desc = (p.get("description") or "").lower()
        groups = p.get("groups") or []
        is_critical_name = False
        for kw in critical_keywords:
            if kw in name or kw in desc:
                is_critical_name = True
                break
        has_groups = len(groups) > 0
        if is_critical_name or has_groups:
            critical_policies.append(p)

    total_critical = len(critical_policies)
    enabled_critical = [p for p in critical_policies if p.get("enabled") is True]
    disabled_names = [p.get("name") or "unknown" for p in critical_policies if not p.get("enabled")]
    enabled_names = [p.get("name") or "unknown" for p in enabled_critical]

    is_enabled = total_critical > 0 and len(enabled_critical) == total_critical

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_critical == 0:
        fail_reasons.append(
            "No prevention policies could be identified as covering critical systems (no policy name/description matched critical keywords and no policy had host groups assigned)."
        )
        recommendations.append(
            "Assign prevention policies explicitly to critical host groups (e.g. servers, domain controllers) and ensure they are enabled."
        )
    elif is_enabled:
        pass_reasons.append(
            "Found %d prevention policy(ies) covering critical systems (%s), all with enabled=true."
            % (total_critical, ", ".join(enabled_names))
        )
    else:
        fail_reasons.append(
            "Of %d prevention policy(ies) covering critical systems, %d are disabled: %s."
            % (total_critical, len(disabled_names), ", ".join(disabled_names))
        )
        recommendations.append(
            "Enable the prevention policy(ies) assigned to critical host groups: %s." % ", ".join(disabled_names)
        )

    result = {
        "isEPPEnabledForCriticalSystems": is_enabled,
        "totalCriticalPolicies": total_critical,
        "enabledCriticalPolicies": len(enabled_critical),
    }

    input_summary = {
        "totalPoliciesEvaluated": len(policies),
        "criticalPoliciesIdentified": total_critical,
        "criticalPoliciesEnabled": len(enabled_critical),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPEnabledForCriticalSystems",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
