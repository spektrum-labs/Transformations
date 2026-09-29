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
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    active_policies = [p for p in policies if isinstance(p, dict) and not p.get("disabled")]

    sms_policy_names = []
    for p in active_policies:
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        factors = obligations.get("mfaFactors") or []
        if not isinstance(factors, list):
            factors = []
        for f in factors:
            if isinstance(f, str) and "sms" in f.lower():
                sms_policy_names.append(p.get("name") or p.get("id") or "unknown")
                break

    total_policies = len(policies)
    total_active = len(active_policies)
    sms_found = len(sms_policy_names) > 0
    is_sms_disabled = not sms_found

    input_summary = {
        "totalPolicies": total_policies,
        "activePolicies": total_active,
        "policiesAllowingSms": len(sms_policy_names),
    }

    if is_sms_disabled:
        pass_reasons = [
            f"Reviewed {total_active} active authentication policies out of {total_policies} total; "
            f"none of their effect.obligations.mfaFactors arrays contain an SMS-type factor, "
            f"indicating SMS is not permitted as an authentication factor."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {len(sms_policy_names)} active policy(ies) permitting SMS as an MFA factor: "
            f"{', '.join(sms_policy_names)}."
        ]
        recommendations = [
            f"Remove SMS from the mfaFactors list on policy(ies) {', '.join(sms_policy_names)} "
            f"and require phishing-resistant factors (e.g. TOTP, WebAuthn) instead."
        ]

    result = {
        "isSmsAuthenticationDisabled": is_sms_disabled,
        "totalPolicies": total_policies,
        "activePolicies": total_active,
        "policiesAllowingSms": len(sms_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSmsAuthenticationDisabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
