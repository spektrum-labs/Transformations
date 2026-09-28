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
        users = data.get("response") or data.get("data") or []
        if not isinstance(users, list):
            users = []
    else:
        users = []

    total_users = len(users)
    enrolled_desktop = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        das = u.get("desktop_authenticators") or []
        if isinstance(das, list) and len(das) > 0:
            enrolled_desktop = enrolled_desktop + 1

    if total_users > 0:
        percentage = round((enrolled_desktop / total_users) * 100.0, 2)
    else:
        percentage = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_users == 0:
        fail_reasons.append("No user records were returned by getUsers; cannot compute desktop authenticator enrollment.")
        recommendations.append("Verify the Duo Admin API credential has read access to /admin/v1/users and that the tenant has users.")
    elif enrolled_desktop == 0:
        fail_reasons.append(
            f"None of the {total_users} users returned by getUsers have a non-empty desktop_authenticators array."
        )
        recommendations.append(
            "Encourage users to enroll a Duo Desktop authenticator, or enforce enrollment via policy."
        )
    else:
        pass_reasons.append(
            f"{enrolled_desktop} of {total_users} users ({percentage}%) have at least one entry in desktop_authenticators."
        )
        if enrolled_desktop < total_users:
            recommendations.append(
                f"{total_users - enrolled_desktop} users have no desktop authenticator enrolled; consider enforcing enrollment for full coverage."
            )

    result = {
        "desktopAuthenticatorEnrollmentPercentage": percentage,
        "totalUsers": total_users,
        "usersWithDesktopAuthenticator": enrolled_desktop,
    }

    input_summary = {
        "totalUsers": total_users,
        "usersWithDesktopAuthenticator": enrolled_desktop,
    }

    metadata = {
        "transformationId": "desktopAuthenticatorEnrollmentPercentage",
        "vendor": "Duo",
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
