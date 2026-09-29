
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
        users = data
        total_count = len(users)
    elif isinstance(data, dict):
        users = data.get("results") or data.get("data") or []
        if not isinstance(users, list):
            users = []
        total_count = data.get("totalCount") or len(users)
    else:
        users = []
        total_count = 0

    mfa_enabled_users = 0
    totp_enabled_users = 0
    portal_mfa_users = 0

    for u in users:
        if not isinstance(u, dict):
            continue
        totp = bool(u.get("totp_enabled"))
        portal_mfa = bool(u.get("enable_user_portal_multifactor"))
        mfa_obj = u.get("mfa") or {}
        mfa_enrollment = u.get("mfaEnrollment") or {}
        has_mfa_factor = False
        if isinstance(mfa_obj, dict):
            for v in mfa_obj.values():
                if v:
                    has_mfa_factor = True
        if isinstance(mfa_enrollment, dict):
            for v in mfa_enrollment.values():
                if v:
                    has_mfa_factor = True

        if totp:
            totp_enabled_users = totp_enabled_users + 1
        if portal_mfa:
            portal_mfa_users = portal_mfa_users + 1
        if totp or portal_mfa or has_mfa_factor:
            mfa_enabled_users = mfa_enabled_users + 1

    sample_size = len(users)
    is_mfa_enabled = mfa_enabled_users > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_mfa_enabled:
        pass_reasons.append(
            f"{mfa_enabled_users} of {sample_size} sampled system users (org totalCount={total_count}) "
            f"show MFA configured: totp_enabled=true for {totp_enabled_users} users and "
            f"enable_user_portal_multifactor=true for {portal_mfa_users} users, evidencing MFA capability "
            f"is enabled and in use within the JumpCloud org."
        )
    else:
        fail_reasons.append(
            f"None of the {sample_size} sampled system users (org totalCount={total_count}) show "
            f"totp_enabled=true, enable_user_portal_multifactor=true, or populated mfa/mfaEnrollment factors."
        )
        recommendations.append(
            "Enable and enforce MFA for users via JumpCloud's Security > MFA Configuration settings "
            "or an authn policy requiring mfa.required=true."
        )

    result = {
        "isMFAEnabled": is_mfa_enabled,
        "totalUsersSampled": sample_size,
        "orgTotalUserCount": total_count,
        "usersWithMfaConfigured": mfa_enabled_users,
        "usersWithTotpEnabled": totp_enabled_users,
        "usersWithPortalMfaEnabled": portal_mfa_users,
    }

    input_summary = {
        "totalUsersSampled": sample_size,
        "orgTotalUserCount": total_count,
        "usersWithMfaConfigured": mfa_enabled_users,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFAEnabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
