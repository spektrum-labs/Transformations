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

    active_users = [u for u in users if isinstance(u, dict) and not u.get("suspended", False)]
    total_active = len(active_users)
    enforced_users = [u for u in active_users if u.get("isEnforcedIn2Sv") is True]
    enforced_count = len(enforced_users)
    not_enforced = [u for u in active_users if not u.get("isEnforcedIn2Sv")]
    not_enforced_emails = [u.get("primaryEmail", "unknown") for u in not_enforced[:10]]

    if total_active == 0:
        is_enforced = False
        fail_reasons = ["No active user records were returned by listDirectoryUsers, so MFA enforcement could not be confirmed."]
        pass_reasons = []
        recommendations = ["Verify the directory API is returning users and re-run this check."]
    elif enforced_count == total_active:
        is_enforced = True
        pass_reasons = [
            f"All {total_active} active (non-suspended) users report isEnforcedIn2Sv=true in the Directory API users.list response."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enforced = False
        pass_reasons = []
        fail_reasons = [
            f"Only {enforced_count} of {total_active} active users have isEnforcedIn2Sv=true. "
            f"Users without 2SV enforcement include: {', '.join(not_enforced_emails)}"
            + (" (and more)" if len(not_enforced) > 10 else "")
        ]
        recommendations = [
            "Enable 2-Step Verification enforcement for all organizational units in the Admin console (Security > Authentication > 2-step verification) so every active user is required to enroll."
        ]

    result = {
        "isMFAEnforcedForUsers": is_enforced,
        "totalActiveUsers": total_active,
        "mfaEnforcedUsers": enforced_count,
    }

    input_summary = {
        "totalUsersInResponse": len(users),
        "totalActiveUsers": total_active,
        "mfaEnforcedUsers": enforced_count,
    }

    metadata = {
        "transformationId": "isMFAEnforcedForUsers",
        "vendor": "Google Gmail Workspace",
        "category": "emailsecurity",
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
