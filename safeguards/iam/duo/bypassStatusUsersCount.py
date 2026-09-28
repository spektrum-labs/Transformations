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
        total_objects = len(users)
    elif isinstance(data, dict):
        users = data.get("response") or []
        if not isinstance(users, list):
            users = []
        metadata = data.get("metadata") or {}
        total_objects = metadata.get("total_objects")
        if not isinstance(total_objects, int):
            total_objects = len(users)
    else:
        users = []
        total_objects = 0

    bypass_users = []
    for u in users:
        if not isinstance(u, dict):
            continue
        status = u.get("status")
        if isinstance(status, str) and status.strip().lower() == "bypass":
            bypass_users.append(u.get("username") or u.get("user_id") or "unknown")

    bypass_count = len(bypass_users)
    total_users = len(users)

    transformation_errors = []
    if total_users == 0:
        transformation_errors.append("No user records found in response")

    if bypass_count > 0:
        sample = bypass_users[:5]
        pass_reasons = [
            f"Found {bypass_count} of {total_users} Duo user accounts with status='bypass' "
            f"(sample usernames: {', '.join([str(s) for s in sample])})."
        ]
        fail_reasons = []
        recommendations = [
            "Review each bypass-status user account and confirm the exemption from second-factor "
            "authentication is still required; revert to enforced status when no longer needed."
        ]
    else:
        pass_reasons = [f"No users among the {total_users} retrieved have status='bypass'."]
        fail_reasons = []
        recommendations = []

    result = {
        "bypassStatusUsersCount": bypass_count,
        "totalUsers": total_users,
    }

    input_summary = {
        "totalUsersRetrieved": total_users,
        "totalObjectsReported": total_objects,
        "bypassStatusUsersCount": bypass_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "bypassStatusUsersCount",
            "vendor": "Duo",
            "category": "iam",
        },
    )
