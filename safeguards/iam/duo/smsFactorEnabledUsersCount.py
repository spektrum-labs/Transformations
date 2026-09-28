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
    else:
        users = []

    if not isinstance(users, list):
        users = []

    sms_enabled_count = 0
    total_users = len(users)
    sample_usernames = []

    for user in users:
        if not isinstance(user, dict):
            continue
        phones = user.get("phones") or []
        if not isinstance(phones, list):
            phones = []
        has_sms = False
        for phone in phones:
            if not isinstance(phone, dict):
                continue
            capabilities = phone.get("capabilities") or []
            if not isinstance(capabilities, list):
                capabilities = []
            if "sms" in capabilities:
                has_sms = True
                break
        if has_sms:
            sms_enabled_count = sms_enabled_count + 1
            if len(sample_usernames) < 5:
                uname = user.get("username") or user.get("user_id") or "unknown"
                sample_usernames.append(uname)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_users == 0:
        fail_reasons.append("No users were returned in the Duo getUsers response, so SMS factor enrollment cannot be evaluated.")
        recommendations.append("Verify the Duo Admin API credential has permission to list users and that the tenant has enrolled users.")
    elif sms_enabled_count > 0:
        pass_reasons.append(
            f"{sms_enabled_count} of {total_users} users have at least one phone entry with 'sms' listed in its capabilities array (sample usernames: {sample_usernames})."
        )
    else:
        fail_reasons.append(
            f"None of the {total_users} users returned have a phone entry with 'sms' in its capabilities array."
        )
        recommendations.append("Enable SMS passcodes as an authentication factor for users' phones in the Duo Admin Panel.")

    result = {
        "smsFactorEnabledUsersCount": sms_enabled_count,
        "totalUsersEvaluated": total_users,
    }

    input_summary = {
        "totalUsersEvaluated": total_users,
        "smsFactorEnabledUsersCount": sms_enabled_count,
    }

    metadata = {
        "transformationId": "smsFactorEnabledUsersCount",
        "vendor": "Duo",
        "category": "Multifactor Authentication",
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
