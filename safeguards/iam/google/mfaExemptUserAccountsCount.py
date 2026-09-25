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
    exempt_users = [
        u for u in active_users
        if u.get("isEnrolledIn2Sv") is False and u.get("isEnforcedIn2Sv") is False
    ]

    exempt_count = len(exempt_users)
    total_active = len(active_users)

    sample_emails = [u.get("primaryEmail", "unknown") for u in exempt_users[:5]]

    if total_active == 0:
        fail_reasons = ["No active user records were found in the Directory API response; cannot evaluate 2SV exemption."]
        pass_reasons = []
        recommendations = ["Verify the listUsers method is returning the active user population."]
    elif exempt_count == 0:
        pass_reasons = [
            f"All {total_active} active users have isEnrolledIn2Sv=true or isEnforcedIn2Sv=true; no users are exempt from 2-step verification."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{exempt_count} of {total_active} active users have both isEnrolledIn2Sv=false and isEnforcedIn2Sv=false (neither opted in nor enforced), e.g. {sample_emails}."
        ]
        recommendations = [
            "Enable 2-Step Verification enforcement policy for the identified users or org units so they are covered even if not individually enrolled."
        ]

    return create_response(
        result={
            "mfaExemptUserAccountsCount": exempt_count,
            "totalActiveUsers": total_active,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalActiveUsers": total_active, "exemptUsers": exempt_count},
        metadata={
            "transformationId": "mfaExemptUserAccountsCount",
            "vendor": "Google",
            "category": "iam",
        },
    )
