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
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    enabled_policies = [p for p in policies if isinstance(p, dict) and not p.get("disabled")]

    strong_policy_names = []
    weak_policy_names = []

    for p in enabled_policies:
        name = p.get("name") or p.get("id") or "unnamed-policy"
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        user_verification = obligations.get("userVerification") or {}
        requirement = str(user_verification.get("requirement") or "none").lower()
        mfa_factors = obligations.get("mfaFactors") or []
        mfa_factors_upper = [str(f).upper() for f in mfa_factors]

        has_webauthn = "WEBAUTHN" in mfa_factors_upper
        strong_verification = requirement in ("required", "preferred", "verified")

        if has_webauthn or strong_verification:
            strong_policy_names.append(name)
        else:
            weak_policy_names.append(name)

    is_strong_auth_required = len(strong_policy_names) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "enabledPolicies": len(enabled_policies),
        "strongAuthPolicies": len(strong_policy_names),
        "weakAuthPolicies": len(weak_policy_names),
    }

    if is_strong_auth_required:
        pass_reasons = [
            f"{len(strong_policy_names)} of {len(enabled_policies)} enabled authn "
            f"policies require strong authentication (WebAuthn factor or "
            f"userVerification requirement), e.g. policy '{strong_policy_names[0]}'."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if enabled_policies:
            example = enabled_policies[0]
            example_name = example.get("name") or example.get("id") or "unnamed-policy"
            example_effect = example.get("effect") or {}
            example_obligations = example_effect.get("obligations") or {}
            example_requirement = (example_obligations.get("userVerification") or {}).get("requirement")
            example_factors = example_obligations.get("mfaFactors") or []
            fail_reasons = [
                f"None of the {len(enabled_policies)} enabled authn policies require "
                f"strong authentication. Example: policy '{example_name}' has "
                f"userVerification.requirement='{example_requirement}' and "
                f"mfaFactors={example_factors} (no WEBAUTHN, no verified requirement)."
            ]
            recommendations = [
                "Configure at least one conditional access policy's effect.obligations "
                "with mfaFactors including WEBAUTHN or userVerification.requirement="
                "'required' to enforce phishing-resistant strong authentication."
            ]
        else:
            fail_reasons = [
                f"No enabled authn policies found among {total_policies} total policies "
                "retrieved from listAuthnPolicies."
            ]
            recommendations = [
                "Create and enable a conditional access policy requiring WebAuthn or "
                "verified user authentication."
            ]

    result = {
        "isStrongAuthRequired": is_strong_auth_required,
        "totalPolicies": total_policies,
        "enabledPolicies": len(enabled_policies),
        "strongAuthPolicies": len(strong_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isStrongAuthRequired",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
