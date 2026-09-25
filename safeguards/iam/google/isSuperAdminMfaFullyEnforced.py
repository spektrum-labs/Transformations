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
        users = data.get("users") or data.get("data") or []
    else:
        users = []

    if not isinstance(users, list):
        users = []

    super_admins = [u for u in users if isinstance(u, dict) and u.get("isAdmin") is True]

    total_super_admins = len(super_admins)
    enforced_count = sum(1 for u in super_admins if u.get("isEnforcedIn2Sv") is True)
    not_enforced = [u for u in super_admins if u.get("isEnforcedIn2Sv") is not True]

    if total_super_admins == 0:
        fully_enforced = False
        pass_reasons = []
        fail_reasons = ["No users with isAdmin=true (Super Admin) were found in the Directory API users.list response, so enforcement cannot be confirmed."]
        recommendations = ["Verify that Super Admin role assignments exist and that the users.list response includes them; re-run once Super Admin accounts are visible."]
    else:
        fully_enforced = (enforced_count == total_super_admins)
        if fully_enforced:
            emails = [u.get("primaryEmail", "unknown") for u in super_admins][:5]
            pass_reasons = [
                f"All {total_super_admins} users with isAdmin=true have isEnforcedIn2Sv=true (e.g. {emails})."
            ]
            fail_reasons = []
            recommendations = []
        else:
            offenders = [u.get("primaryEmail", "unknown") for u in not_enforced][:10]
            pass_reasons = []
            fail_reasons = [
                f"{len(not_enforced)} of {total_super_admins} Super Admin users (isAdmin=true) do not have isEnforcedIn2Sv=true. Examples: {offenders}."
            ]
            recommendations = [
                "Enable and enforce 2-Step Verification for all Super Admin accounts listed above via Admin console Security > Authentication > 2-Step Verification."
            ]

    result = {
        "isSuperAdminMfaFullyEnforced": fully_enforced,
        "totalSuperAdmins": total_super_admins,
        "superAdminsWithMfaEnforced": enforced_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalUsersInResponse": len(users),
            "totalSuperAdmins": total_super_admins,
            "superAdminsWithMfaEnforced": enforced_count,
        },
        metadata={
            "transformationId": "isSuperAdminMfaFullyEnforced",
            "vendor": "Google",
            "category": "iam",
        },
    )
