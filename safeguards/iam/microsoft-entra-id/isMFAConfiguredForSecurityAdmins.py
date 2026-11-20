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
    elif isinstance(data, dict):
        users = data.get("value") or data.get("data") or []
    else:
        users = []

    if not isinstance(users, list):
        users = []

    admin_users = [u for u in users if isinstance(u, dict) and u.get("isAdmin") is True]
    total_admins = len(admin_users)
    admins_with_mfa = [u for u in admin_users if u.get("isMfaRegistered") is True]
    admins_with_mfa_count = len(admins_with_mfa)
    admins_missing_mfa = [
        u.get("userDisplayName") or u.get("userPrincipalName") or u.get("id") or "unknown"
        for u in admin_users
        if not u.get("isMfaRegistered")
    ]

    if total_admins == 0:
        result_bool = False
        fail_reasons = [
            "No admin accounts (isAdmin=true) were found in userRegistrationDetails, so MFA configuration for security admins could not be confirmed."
        ]
        pass_reasons = []
        recommendations = [
            "Verify that privileged/admin role assignments exist and that the reporting API correctly flags them with isAdmin=true."
        ]
    else:
        result_bool = admins_with_mfa_count == total_admins
        if result_bool:
            pass_reasons = [
                f"All {total_admins} admin accounts (isAdmin=true) in userRegistrationDetails report isMfaRegistered=true."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            missing_sample = admins_missing_mfa[:10]
            fail_reasons = [
                f"{admins_with_mfa_count} of {total_admins} admin accounts have isMfaRegistered=true; "
                f"{total_admins - admins_with_mfa_count} admin account(s) lack MFA registration, e.g. {missing_sample}."
            ]
            recommendations = [
                "Require MFA registration for all accounts holding privileged/admin directory roles, e.g. via a Conditional Access policy targeting admin roles with grantControls requiring mfa."
            ]

    result = {
        "isMFAConfiguredForSecurityAdmins": result_bool,
        "totalAdmins": total_admins,
        "adminsWithMfaRegistered": admins_with_mfa_count,
    }

    input_summary = {
        "totalUsersEvaluated": len(users),
        "totalAdmins": total_admins,
        "adminsWithMfaRegistered": admins_with_mfa_count,
    }

    metadata = {
        "transformationId": "isMFAConfiguredForSecurityAdmins",
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
