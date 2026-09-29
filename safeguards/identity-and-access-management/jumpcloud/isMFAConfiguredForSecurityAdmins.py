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

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    admin_policies = []
    admin_mfa_required_policies = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        ptype = p.get("type") or ""
        targets = p.get("targets") or {}
        resources = targets.get("resources") or []
        resource_types = [r.get("type") for r in resources if isinstance(r, dict)]
        is_admin_scope = ptype == "admin_portal" or "admin_portal" in resource_types

        if is_admin_scope:
            admin_policies.append(p)
            disabled = bool(p.get("disabled"))
            effect = p.get("effect") or {}
            obligations = effect.get("obligations") or {}
            mfa_obj = obligations.get("mfa") or {}
            mfa_required = bool(mfa_obj.get("required"))
            if mfa_required and not disabled:
                admin_mfa_required_policies.append(p)

    total_admin_policies = len(admin_policies)
    total_enforcing = len(admin_mfa_required_policies)
    is_configured = total_enforcing > 0

    admin_policy_names = [p.get("name") or p.get("id") or "unnamed" for p in admin_policies]
    enforcing_names = [p.get("name") or p.get("id") or "unnamed" for p in admin_mfa_required_policies]

    if is_configured:
        pass_reasons = [
            f"Found {total_enforcing} admin_portal-scoped authn policy(ies) with effect.obligations.mfa.required=true and disabled=false: {enforcing_names}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_admin_policies == 0:
            fail_reasons = [
                "No authn policy targeting admin_portal (security admin) resources was found among the "
                f"{len(policies)} policies retrieved from listAuthnPolicies."
            ]
        else:
            fail_reasons = [
                f"Found {total_admin_policies} admin_portal-scoped policy(ies) ({admin_policy_names}) but none has "
                "effect.obligations.mfa.required=true while enabled (disabled=false)."
            ]
        recommendations = [
            "Create or enable a Conditional Access Policy targeting the Admin Portal (admin_portal resource type) "
            "with effect.obligations.mfa.required=true to enforce MFA for security administrators."
        ]

    result = {
        "isMFAConfiguredForSecurityAdmins": is_configured,
        "totalAdminPortalPolicies": total_admin_policies,
        "adminPortalPoliciesRequiringMfa": total_enforcing,
    }

    input_summary = {
        "totalPoliciesRetrieved": len(policies),
        "totalAdminPortalPolicies": total_admin_policies,
        "adminPortalPoliciesRequiringMfa": total_enforcing,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFAConfiguredForSecurityAdmins",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
