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
    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    active_policies = [p for p in policies if isinstance(p, dict) and not p.get("disabled")]

    enforced_policy_names = []
    enforced_user_scope_policy_names = []

    for p in active_policies:
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_ob = obligations.get("mfa") or {}
        mfa_required = bool(mfa_ob.get("required"))
        if mfa_required:
            name = p.get("name") or p.get("id") or "unnamed-policy"
            enforced_policy_names.append(name)
            ptype = p.get("type") or ""
            if ptype in ("user_portal", "sso", "admin_portal"):
                enforced_user_scope_policy_names.append(name + " (type=" + ptype + ")")

    is_mfa_enforced = len(enforced_policy_names) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "activePolicies": len(active_policies),
        "enforcedPolicyCount": len(enforced_policy_names),
    }

    if is_mfa_enforced:
        pass_reasons = [
            str(len(enforced_policy_names)) + " of " + str(len(active_policies)) +
            " active authentication policies have effect.obligations.mfa.required=true: " +
            ", ".join(enforced_policy_names) + "."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "None of the " + str(len(active_policies)) + " active authentication policies (out of " +
            str(total_policies) + " total) have effect.obligations.mfa.required=true."
        ]
        recommendations = [
            "Configure a JumpCloud Conditional Access Policy targeting user_portal (or admin_portal) "
            "with effect.obligations.mfa.required=true to enforce MFA org-wide."
        ]

    return create_response(
        result={
            "isMFAEnforced": is_mfa_enforced,
            "totalPolicies": total_policies,
            "activePolicies": len(active_policies),
            "enforcedPolicyCount": len(enforced_policy_names),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFAEnforced",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
