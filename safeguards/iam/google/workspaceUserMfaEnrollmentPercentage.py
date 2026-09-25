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
        users = data.get("users") or data.get("data") or []
    else:
        users = []

    if not isinstance(users, list):
        users = []

    active_users = [u for u in users if isinstance(u, dict) and not u.get("suspended", False)]
    total_active = len(active_users)
    enrolled_active = [u for u in active_users if u.get("isEnrolledIn2Sv") is True]
    enrolled_count = len(enrolled_active)

    if total_active == 0:
        percentage = 0.0
    else:
        percentage = round((enrolled_count / total_active) * 100.0, 2)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_active == 0:
        fail_reasons.append("No active (non-suspended) users were found in the Directory API users.list response, so enrollment percentage could not be computed.")
        recommendations.append("Verify the listUsers call returns active users for this domain.")
    elif enrolled_count == total_active:
        pass_reasons.append(
            f"All {total_active} active users have isEnrolledIn2Sv=true across the Directory API users.list response."
        )
    else:
        not_enrolled = total_active - enrolled_count
        pass_reasons.append(
            f"{enrolled_count} of {total_active} active users report isEnrolledIn2Sv=true ({percentage}% enrollment)."
        )
        if percentage < 100:
            fail_reasons.append(
                f"{not_enrolled} of {total_active} active users have isEnrolledIn2Sv=false, resulting in {percentage}% enrollment (below 100%)."
            )
            sample_unenrolled = [u.get("primaryEmail", "unknown") for u in active_users if u.get("isEnrolledIn2Sv") is not True][:5]
            recommendations.append(
                f"Encourage or enforce 2-Step Verification enrollment for unenrolled active users, e.g.: {', '.join(sample_unenrolled)}."
            )

    input_summary = {
        "totalActiveUsers": total_active,
        "enrolledActiveUsers": enrolled_count,
        "totalUsersInResponse": len(users),
    }

    result = {
        "workspaceUserMfaEnrollmentPercentage": percentage,
        "totalActiveUsers": total_active,
        "enrolledActiveUsers": enrolled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "workspaceUserMfaEnrollmentPercentage",
            "vendor": "Google",
            "category": "iam",
        },
    )
