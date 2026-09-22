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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    enforce_strong = data.get("enforceStrongPasswords")
    min_length = data.get("minimumPasswordLength")

    transformation_errors = []

    is_bool_enforced = enforce_strong is True

    min_length_ok = False
    if isinstance(min_length, (int, float)):
        min_length_ok = min_length >= 8

    is_enforced = bool(is_bool_enforced and (min_length_ok or not isinstance(min_length, (int, float))))

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enforce_strong is True:
        if isinstance(min_length, (int, float)):
            pass_reasons.append(
                f"enforceStrongPasswords is true with minimumPasswordLength={min_length}, meeting the strong password policy requirement."
            )
        else:
            pass_reasons.append("enforceStrongPasswords is true (minimumPasswordLength not reported).")
    else:
        fail_reasons.append(
            f"enforceStrongPasswords is {enforce_strong!r}; the organization's Dashboard login security settings do not enforce a strong admin password policy."
        )
        recommendations.append(
            "Enable 'Require strong passwords' with a minimum length of at least 8 characters under Organization > Settings > Login security in the Meraki Dashboard."
        )

    if isinstance(min_length, (int, float)) and min_length < 8 and enforce_strong is True:
        is_enforced = False
        fail_reasons.append(
            f"minimumPasswordLength is {min_length}, below the recommended minimum of 8 characters."
        )
        recommendations.append("Increase minimumPasswordLength to at least 8 characters.")

    result = {
        "isStrongPasswordPolicyEnforced": is_enforced,
        "enforceStrongPasswords": enforce_strong,
        "minimumPasswordLength": min_length,
    }

    input_summary = {
        "enforceStrongPasswords": enforce_strong,
        "minimumPasswordLength": min_length,
    }

    metadata = {
        "transformationId": "isStrongPasswordPolicyEnforced",
        "vendor": "Cisco Meraki MX",
        "category": "firewalls",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        transformation_errors=transformation_errors,
    )
