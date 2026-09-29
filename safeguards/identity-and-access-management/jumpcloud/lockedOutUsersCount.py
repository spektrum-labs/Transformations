
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
        total_count = data.get("totalCount")
        if not isinstance(total_count, int):
            total_count = len(users)
    else:
        users = []
        total_count = 0

    locked_users = [u for u in users if isinstance(u, dict) and u.get("account_locked") is True]
    locked_count = len(locked_users)

    locked_usernames = [u.get("username") or u.get("email") or u.get("_id") for u in locked_users][:10]

    if users:
        if locked_count > 0:
            pass_reasons = [
                f"Found {locked_count} locked-out user(s) out of {len(users)} system user records inspected (account_locked=true). Examples: {locked_usernames}"
            ]
            fail_reasons = []
            recommendations = [
                "Review locked-out accounts and confirm they are the result of legitimate failed login attempts, then unlock or reset as appropriate."
            ]
        else:
            pass_reasons = [
                f"No users have account_locked=true across {len(users)} system user records inspected."
            ]
            fail_reasons = []
            recommendations = []
    else:
        pass_reasons = []
        fail_reasons = ["No system user records were returned by listSystemUsers; unable to determine locked-out user count."]
        recommendations = ["Verify API connectivity and permissions for the systemusers endpoint."]

    result = {
        "lockedOutUsersCount": locked_count,
        "usersInspected": len(users),
        "totalUsersReported": total_count,
    }

    input_summary = {
        "usersInspected": len(users),
        "totalUsersReported": total_count,
        "lockedOutUsersCount": locked_count,
    }

    metadata = {
        "transformationId": "lockedOutUsersCount",
        "vendor": "JumpCloud",
        "category": "identity-and-access-management",
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
