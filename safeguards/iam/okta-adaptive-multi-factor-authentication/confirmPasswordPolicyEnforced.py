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
        policies = data.get("data") or data.get("policies") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    active_policies = []
    enforced_policies = []
    inspected_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        status = p.get("status") or ""
        settings = p.get("settings") or {}
        name = p.get("name") or p.get("id") or "unknown"
        inspected_names.append(f"{name}({status})")
        if status == "ACTIVE":
            active_policies.append(p)
            password_settings = settings.get("password") if isinstance(settings, dict) else None
            if password_settings:
                enforced_policies.append(p)

    total_policies = len(policies)
    total_active = len(active_policies)
    total_enforced = len(enforced_policies)

    is_enforced = total_enforced > 0

    if is_enforced:
        names = ", ".join([p.get("name") or p.get("id") or "unknown" for p in enforced_policies])
        pass_reasons = [
            f"{total_enforced} of {total_active} ACTIVE password policies carry a non-empty settings.password object (policies: {names}), confirming a password policy is enforced."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_active} ACTIVE password policies (out of {total_policies} total PASSWORD-type policies) carry a populated settings.password object."
        ]
        recommendations = [
            "Configure and activate a password policy in Okta with settings.password complexity rules defined (minLength, age, lockout)."
        ]

    result = {
        "confirmPasswordPolicyEnforced": is_enforced,
        "totalPasswordPolicies": total_policies,
        "activePasswordPolicies": total_active,
        "enforcedPasswordPolicies": total_enforced,
    }

    input_summary = {
        "totalPolicies": total_policies,
        "activePolicies": total_active,
        "enforcedPolicies": total_enforced,
        "inspected": inspected_names,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "confirmPasswordPolicyEnforced",
            "vendor": "Okta Adaptive Multi Factor Authentication",
            "category": "iam",
        },
    )
