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
        policies = data.get("apiResponse") or data.get("data") or data.get("results") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    active_policies = [p for p in policies if isinstance(p, dict) and p.get("status") == "ACTIVE"]

    non_mfa_password_only = ["okta_password", "password"]

    enforced_policy_names = []
    unenforced_policy_names = []

    for p in active_policies:
        name = p.get("name") or p.get("id") or "unnamed policy"
        settings = p.get("settings") or {}
        requires_non_password_factor = False

        authenticators = settings.get("authenticators")
        if isinstance(authenticators, list):
            for a in authenticators:
                if not isinstance(a, dict):
                    continue
                key = a.get("key") or ""
                if key in non_mfa_password_only:
                    continue
                enroll = a.get("enroll") or {}
                if enroll.get("self") == "REQUIRED":
                    requires_non_password_factor = True
                    break

        factors = settings.get("factors")
        if not requires_non_password_factor and isinstance(factors, dict):
            for fkey, fval in factors.items():
                if fkey in non_mfa_password_only:
                    continue
                if not isinstance(fval, dict):
                    continue
                enroll = fval.get("enroll") or {}
                if enroll.get("self") == "REQUIRED":
                    requires_non_password_factor = True
                    break

        if requires_non_password_factor:
            enforced_policy_names.append(name)
        else:
            unenforced_policy_names.append(name)

    total_active = len(active_policies)
    is_enforced = total_active > 0 and len(unenforced_policy_names) == 0

    input_summary = {
        "totalPolicies": len(policies),
        "activePolicies": total_active,
        "enforcedPolicies": enforced_policy_names,
        "unenforcedPolicies": unenforced_policy_names,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        pass_reasons.append(
            "All %d ACTIVE MFA_ENROLL polic%s (%s) require at least one non-password authenticator (e.g. okta_verify, phone_number, okta_otp, okta_sms, security_question) marked enroll.self=REQUIRED."
            % (total_active, "y" if total_active == 1 else "ies", ", ".join(enforced_policy_names))
        )
    else:
        if total_active == 0:
            fail_reasons.append("No ACTIVE MFA_ENROLL policies were found; MFA enrollment is not enforced for any group.")
            recommendations.append("Create and activate an MFA_ENROLL policy that marks a non-password authenticator as REQUIRED.")
        else:
            fail_reasons.append(
                "The following ACTIVE MFA_ENROLL policies do not require any non-password authenticator (only password or no factor is REQUIRED): %s."
                % ", ".join(unenforced_policy_names)
            )
            recommendations.append(
                "Update policies %s to mark at least one non-password authenticator (okta_verify, phone_number, okta_otp, okta_sms, security_question) as enroll.self=REQUIRED."
                % ", ".join(unenforced_policy_names)
            )
        if enforced_policy_names:
            pass_reasons.append(
                "Policies %s already require a non-password authenticator." % ", ".join(enforced_policy_names)
            )

    result = {
        "isMFAEnforcedForUsers": is_enforced,
        "totalActivePolicies": total_active,
        "enforcedPolicyCount": len(enforced_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFAEnforcedForUsers",
            "vendor": "Okta Adaptive Multi Factor Authentication",
            "category": "iam",
        },
    )
