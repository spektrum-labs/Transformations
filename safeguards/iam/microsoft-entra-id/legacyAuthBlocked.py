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

    legacy_client_types = ["exchangeActiveSync", "other"]

    blocking_policies = []
    enabled_policy_count = 0

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        state = policy.get("state")
        if state == "enabled":
            enabled_policy_count = enabled_policy_count + 1
        conditions = policy.get("conditions") or {}
        client_app_types = conditions.get("clientAppTypes") or []
        grant_controls = policy.get("grantControls") or {}
        built_in_controls = grant_controls.get("builtInControls") or []

        targets_legacy = False
        for legacy_type in legacy_client_types:
            if legacy_type in client_app_types:
                targets_legacy = True
        if "all" in client_app_types:
            targets_legacy = True

        blocks_access = "block" in built_in_controls

        if state == "enabled" and targets_legacy and blocks_access:
            blocking_policies.append({
                "id": policy.get("id"),
                "displayName": policy.get("displayName"),
                "clientAppTypes": client_app_types,
                "builtInControls": built_in_controls,
            })

    is_blocked = len(blocking_policies) > 0

    total_policies = len(policies)

    if is_blocked:
        names = ", ".join([p.get("displayName") or p.get("id") or "unknown" for p in blocking_policies])
        pass_reasons = [
            f"Found {len(blocking_policies)} enabled Conditional Access policy/policies with grantControls.builtInControls containing 'block' and conditions.clientAppTypes targeting legacy auth clients (exchangeActiveSync/other/all): {names}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_policies} Conditional Access policies inspected ({enabled_policy_count} enabled) have both state=enabled, grantControls.builtInControls containing 'block', and conditions.clientAppTypes targeting legacy authentication clients (exchangeActiveSync/other/all)."
        ]
        recommendations = [
            "Create and enable a Conditional Access policy that targets clientAppTypes=['exchangeActiveSync','other'] with grantControls.builtInControls=['block'] to block legacy authentication tenant-wide."
        ]

    result = {
        "legacyAuthBlocked": is_blocked,
        "totalPoliciesEvaluated": total_policies,
        "enabledPolicyCount": enabled_policy_count,
        "blockingPolicyCount": len(blocking_policies),
    }

    input_summary = {
        "totalPolicies": total_policies,
        "enabledPolicies": enabled_policy_count,
        "blockingPolicies": len(blocking_policies),
    }

    metadata = {
        "transformationId": "legacyAuthBlocked",
        "vendor": "Microsoft Entra ID",
        "category": "iam",
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
