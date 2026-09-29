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

    suspended_users = [
        u for u in users
        if isinstance(u, dict) and (
            u.get("suspended") is True or u.get("state") == "SUSPENDED"
        )
    ]
    suspended_count = len(suspended_users)
    fetched_count = len(users)

    sample_names = []
    for u in suspended_users[:5]:
        uname = u.get("username") or u.get("email") or u.get("_id") or "unknown"
        sample_names.append(uname)

    if suspended_count > 0:
        pass_reasons = [
            f"Found {suspended_count} suspended user(s) out of {fetched_count} fetched system users "
            f"(org totalCount reported as {total_count}). Suspended flag or state='SUSPENDED' drove this count. "
            f"Examples: {', '.join(str(s) for s in sample_names)}."
        ]
    else:
        pass_reasons = [
            f"No suspended users found among {fetched_count} fetched system users "
            f"(org totalCount reported as {total_count}); suspended field and state field both show no SUSPENDED entries."
        ]
    fail_reasons = []
    recommendations = []
    if suspended_count > 0:
        recommendations = [
            "Review the suspended user accounts listed and remove or fully deprovision them if no longer needed, "
            "since suspended accounts can still represent residual access risk in JumpCloud."
        ]

    result = {
        "suspendedUsersCount": suspended_count,
        "totalUsersFetched": fetched_count,
        "totalUsersReported": total_count,
    }

    input_summary = {
        "totalUsersFetched": fetched_count,
        "totalUsersReported": total_count,
        "suspendedUsersCount": suspended_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "suspendedUsersCount",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
