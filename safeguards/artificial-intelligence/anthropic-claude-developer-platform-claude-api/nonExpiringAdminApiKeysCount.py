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
        keys = data
    elif isinstance(data, dict):
        keys = data.get("data") or []
    else:
        keys = []

    if not isinstance(keys, list):
        keys = []

    total_keys = len(keys)
    active_keys = [k for k in keys if isinstance(k, dict) and k.get("status") == "active"]
    non_expiring_active = [k for k in active_keys if k.get("expires_at") is None]
    non_expiring_all = [k for k in keys if isinstance(k, dict) and k.get("expires_at") is None]

    count = len(non_expiring_active)
    non_expiring_names = [k.get("name") or k.get("id") or "unknown" for k in non_expiring_active]

    result = {
        "nonExpiringAdminApiKeysCount": count,
        "totalApiKeys": total_keys,
        "totalActiveApiKeys": len(active_keys),
        "totalNonExpiringKeysIncludingArchived": len(non_expiring_all),
    }

    if total_keys == 0:
        fail_reasons = ["No organization API keys were returned by listApiKeys; cannot determine non-expiring key count from an empty fleet."]
        pass_reasons = []
        recommendations = ["Confirm the Admin API key has permission to list organization API keys and that the organization actually has keys provisioned."]
    elif count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{count} of {len(active_keys)} active organization API keys have a null expires_at (never expire): {', '.join(non_expiring_names)}."
        ]
        recommendations = [
            "Set an explicit expiration on the listed organization API keys that currently never expire, and rotate them regularly.",
        ]
    else:
        pass_reasons = [
            f"All {len(active_keys)} active organization API keys (out of {total_keys} total keys) have a non-null expires_at."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalApiKeys": total_keys,
            "totalActiveApiKeys": len(active_keys),
            "nonExpiringActiveApiKeys": count,
        },
        metadata={"transformationId": "nonExpiringAdminApiKeysCount", "vendor": "Anthropic", "category": "artificial-intelligence"},
    )
