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
        users = data
    elif isinstance(data, dict):
        users = data.get("users") or []
    else:
        users = []

    if not isinstance(users, list):
        users = []

    super_admins = []
    super_admins_without_mfa = []

    for u in users:
        if not isinstance(u, dict):
            continue
        is_admin = bool(u.get("isAdmin"))
        if not is_admin:
            continue
        super_admins.append(u)
        is_enforced = bool(u.get("isEnforcedIn2Sv"))
        if not is_enforced:
            super_admins_without_mfa.append(u)

    total_super_admins = len(super_admins)
    without_mfa_count = len(super_admins_without_mfa)

    sample_emails = []
    for u in super_admins_without_mfa[:5]:
        email = u.get("primaryEmail") or "<unknown>"
        sample_emails.append(email)

    if total_super_admins == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        pass_reasons.append(
            "No users with isAdmin=true were found in the listUsers response "
            "(0 of %d users are super admins), so superAdminAccountsWithoutMfaCount is 0." % len(users)
        )
    elif without_mfa_count == 0:
        pass_reasons = [
            "All %d super admin accounts (isAdmin=true) report isEnforcedIn2Sv=true; "
            "0 super admins lack enforced MFA." % total_super_admins
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "%d of %d super admin accounts (isAdmin=true) have isEnforcedIn2Sv=false: %s"
            % (without_mfa_count, total_super_admins, ", ".join(sample_emails))
        ]
        recommendations = [
            "Enforce 2-Step Verification for all Super Admin accounts in the Google Workspace "
            "Admin console (Security > Authentication > 2-Step Verification) so that "
            "isEnforcedIn2Sv=true for every super admin."
        ]

    result = {
        "superAdminAccountsWithoutMfaCount": without_mfa_count,
        "totalSuperAdmins": total_super_admins,
        "totalUsersEvaluated": len(users),
    }

    input_summary = {
        "totalUsersEvaluated": len(users),
        "totalSuperAdmins": total_super_admins,
        "superAdminsWithoutMfa": without_mfa_count,
    }

    metadata = {
        "transformationId": "superAdminAccountsWithoutMfaCount",
        "vendor": "Google",
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
