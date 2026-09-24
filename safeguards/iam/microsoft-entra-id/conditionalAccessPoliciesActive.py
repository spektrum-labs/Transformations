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
        policies = data.get("value") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    enabled_policies = []
    report_only_policies = []
    disabled_policies = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        state = p.get("state") or ""
        name = p.get("displayName") or p.get("id") or "unknown"
        if state == "enabled":
            enabled_policies.append(name)
        elif state == "enabledForReportingButNotEnforced":
            report_only_policies.append(name)
        elif state == "disabled":
            disabled_policies.append(name)

    enabled_count = len(enabled_policies)
    report_only_count = len(report_only_policies)
    disabled_count = len(disabled_policies)

    is_active = enabled_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_active:
        sample = ", ".join(enabled_policies[:5])
        pass_reasons.append(
            f"{enabled_count} of {total_policies} Conditional Access policies have state='enabled' "
            f"(e.g. {sample}), confirming Conditional Access is actively enforced in this tenant."
        )
        if report_only_count > 0:
            pass_reasons.append(
                f"An additional {report_only_count} policies are in report-only mode "
                f"(enabledForReportingButNotEnforced), not counted as enforced but present."
            )
    else:
        fail_reasons.append(
            f"None of the {total_policies} Conditional Access policies returned have state='enabled'. "
            f"{report_only_count} are report-only and {disabled_count} are disabled."
        )
        recommendations.append(
            "Enable at least one Conditional Access policy (set state to 'enabled') to enforce "
            "access controls such as MFA for the tenant."
        )

    result = {
        "conditionalAccessPoliciesActive": is_active,
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_count,
        "reportOnlyPolicies": report_only_count,
        "disabledPolicies": disabled_count,
    }

    input_summary = {
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_count,
        "reportOnlyPolicies": report_only_count,
        "disabledPolicies": disabled_count,
    }

    metadata = {
        "transformationId": "conditionalAccessPoliciesActive",
        "vendor": "Microsoft Entra ID",
        "category": "Multifactor Authentication",
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
