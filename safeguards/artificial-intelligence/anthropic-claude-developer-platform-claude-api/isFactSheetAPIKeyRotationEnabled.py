
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
        keys = data
    elif isinstance(data, dict):
        keys = data.get("data") or []
    else:
        keys = []

    total_keys = len(keys)
    keys_with_expiry = []
    keys_without_expiry = []

    for k in keys:
        if not isinstance(k, dict):
            continue
        expires_at = k.get("expires_at")
        name = k.get("name") or k.get("id") or "unknown"
        status = k.get("status") or "unknown"
        if expires_at:
            keys_with_expiry.append(name)
        else:
            keys_without_expiry.append({"name": name, "status": status})

    with_count = len(keys_with_expiry)
    without_count = len(keys_without_expiry)

    if total_keys == 0:
        result_bool = False
        pass_reasons = []
        fail_reasons = ["No API keys were returned by listApiKeys, so no rotation policy could be verified."]
        recommendations = ["Confirm the Admin API key has access to organization API keys, or create at least one API key with an expires_at value."]
    elif without_count == 0:
        result_bool = True
        pass_reasons = [
            f"All {total_keys} organization API keys carry a non-null expires_at value "
            f"(e.g. {', '.join(keys_with_expiry[:5])}), evidencing an enforced rotation schedule."
        ]
        fail_reasons = []
        recommendations = []
    else:
        result_bool = False
        pass_reasons = []
        sample_names = [x["name"] for x in keys_without_expiry[:5]]
        fail_reasons = [
            f"{without_count} of {total_keys} organization API keys have no expires_at value "
            f"(no enforced expiration), including: {', '.join(sample_names)}."
        ]
        recommendations = [
            "Rotate and reissue the listed API keys with an expires_at value set, or configure an "
            "org-wide key rotation policy so every key is created with a defined expiration."
        ]

    input_summary = {
        "totalApiKeys": total_keys,
        "keysWithExpiresAt": with_count,
        "keysWithoutExpiresAt": without_count,
    }

    return create_response(
        result={
            "isFactSheetAPIKeyRotationEnabled": result_bool,
            "totalApiKeys": total_keys,
            "keysWithExpiresAt": with_count,
            "keysWithoutExpiresAt": without_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isFactSheetAPIKeyRotationEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "Artificial Intelligence",
        },
    )
