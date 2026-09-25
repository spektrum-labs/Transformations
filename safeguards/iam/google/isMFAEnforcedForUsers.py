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

    active_users = [u for u in users if isinstance(u, dict) and not u.get("suspended")]
    total_active = len(active_users)
    enforced_users = [u for u in active_users if u.get("isEnforcedIn2Sv") is True]
    enforced_count = len(enforced_users)
    not_enforced = [u.get("primaryEmail") or u.get("id") or "unknown" for u in active_users if not u.get("isEnforcedIn2Sv")]

    if total_active == 0:
        is_enforced = False
        fail_reasons = ["No active user records were returned to evaluate 2-step verification enforcement."]
        pass_reasons = []
        recommendations = ["Verify the Directory API scope and re-run the users.list call to confirm user data is retrievable."]
    else:
        is_enforced = enforced_count == total_active
        if is_enforced:
            pass_reasons = [f"All {total_active} active (non-suspended) users report isEnforcedIn2Sv=true."]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            sample = not_enforced[:5]
            fail_reasons = [
                f"{enforced_count} of {total_active} active users have isEnforcedIn2Sv=true; "
                f"{total_active - enforced_count} users are not enforced, e.g. {sample}."
            ]
            recommendations = [
                "Enable 2-step verification enforcement for all organizational units in Google Admin Console "
                "(Security > Authentication > 2-Step Verification > Enforcement)."
            ]

    result = {
        "isMFAEnforcedForUsers": is_enforced,
        "totalActiveUsers": total_active,
        "mfaEnforcedUserCount": enforced_count,
    }

    input_summary = {
        "totalUsersInResponse": len(users),
        "totalActiveUsers": total_active,
        "mfaEnforcedUserCount": enforced_count,
    }

    metadata = {
        "transformationId": "isMFAEnforcedForUsers",
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
