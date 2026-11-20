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
    elif isinstance(data, dict):
        policies = data.get("value") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)

    mfa_policies = []
    weak_mfa_policies = []
    strong_policy_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        requirements = p.get("requirementsSatisfied") or ""
        combos = p.get("allowedCombinations") or []
        display_name = p.get("displayName") or p.get("id") or "unknown"
        if requirements == "mfa":
            mfa_policies.append(p)
            is_weak = False
            for c in combos:
                if c == "password":
                    is_weak = True
            if is_weak:
                weak_mfa_policies.append(display_name)
            else:
                strong_policy_names.append(display_name)

    mfa_policy_count = len(mfa_policies)
    weak_count = len(weak_mfa_policies)
    strong_count = len(strong_policy_names)

    is_strong_auth_required = mfa_policy_count > 0 and weak_count == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_strong_auth_required:
        names_str = ", ".join(strong_policy_names[:5])
        pass_reasons.append(
            f"Found {mfa_policy_count} authenticationStrengthPolicy object(s) with requirementsSatisfied='mfa' "
            f"(e.g. {names_str}) and none of them allow a bare 'password' single-factor combination to satisfy "
            f"the MFA requirement, indicating strong authentication combinations are enforced by policy definition."
        )
    else:
        if mfa_policy_count == 0:
            fail_reasons.append(
                f"No authenticationStrengthPolicy objects were found with requirementsSatisfied='mfa' "
                f"out of {total_policies} total policies retrieved from policies/authenticationStrengthPolicies."
            )
            recommendations.append(
                "Define or enable an authentication strength policy (e.g. built-in 'Multifactor authentication' "
                "or 'Phishing-resistant MFA') and reference it from a Conditional Access grant control."
            )
        if weak_count > 0:
            weak_names_str = ", ".join(weak_mfa_policies[:5])
            fail_reasons.append(
                f"{weak_count} of {mfa_policy_count} policies marked requirementsSatisfied='mfa' still list a bare "
                f"'password' single-factor combination in allowedCombinations (e.g. {weak_names_str}), meaning "
                f"password alone can satisfy an 'mfa' authentication strength requirement."
            )
            recommendations.append(
                "Remove the standalone 'password' entry from allowedCombinations on any authentication strength "
                "policy that is meant to enforce a strong/multi-factor requirement."
            )

    result = {
        "isStrongAuthRequired": is_strong_auth_required,
        "totalAuthStrengthPolicies": total_policies,
        "mfaSatisfyingPolicies": mfa_policy_count,
        "weakMfaPolicies": weak_count,
    }

    input_summary = {
        "totalAuthStrengthPolicies": total_policies,
        "mfaSatisfyingPolicies": mfa_policy_count,
        "strongPolicyNames": strong_policy_names,
        "weakMfaPolicyNames": weak_mfa_policies,
    }

    metadata = {
        "transformationId": "isStrongAuthRequired",
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
