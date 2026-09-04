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

    enforce_lockout = data.get("enforceAccountLockout")
    if enforce_lockout is None:
        enforce_lockout = False

    raw_attempts = data.get("accountLockoutAttempts")

    threshold = None
    if isinstance(raw_attempts, (int, float)) and not isinstance(raw_attempts, bool):
        threshold = int(raw_attempts)
    elif isinstance(raw_attempts, list) and len(raw_attempts) > 0:
        first = raw_attempts[0]
        if isinstance(first, (int, float)) and not isinstance(first, bool):
            threshold = int(first)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enforce_lockout and threshold is not None and threshold > 0:
        pass_reasons.append(
            f"Organization login security enforces account lockout (enforceAccountLockout=true) "
            f"with accountLockoutAttempts={threshold}, a bounded failed-login threshold."
        )
    else:
        fail_reasons.append(
            f"Organization login security does not enforce a bounded account lockout threshold "
            f"(enforceAccountLockout={enforce_lockout}, accountLockoutAttempts={raw_attempts})."
        )
        recommendations.append(
            "Enable account lockout after failed Dashboard login attempts in Organization > "
            "Settings > Login security, and set accountLockoutAttempts to a bounded value (e.g. 5)."
        )
        if threshold is None:
            threshold = 0

    result = {
        "adminLockoutThresholdCount": threshold if threshold is not None else 0,
        "enforceAccountLockout": bool(enforce_lockout),
    }

    input_summary = {
        "enforceAccountLockout": enforce_lockout,
        "accountLockoutAttempts": raw_attempts,
    }

    metadata = {
        "transformationId": "adminLockoutThresholdCount",
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
    )
