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
        authenticators = data
    elif isinstance(data, dict):
        authenticators = data.get("apiResponse") or data.get("data") or []
    else:
        authenticators = []

    if not isinstance(authenticators, list):
        authenticators = []

    active_types = []
    inactive_types = []
    for a in authenticators:
        if not isinstance(a, dict):
            continue
        key = a.get("key") or a.get("type") or "unknown"
        status = a.get("status") or ""
        if status == "ACTIVE":
            active_types.append(key)
        else:
            inactive_types.append(key)

    total = len(authenticators)
    active_count = len(active_types)

    result = {
        "authTypesAllowed": active_types,
        "totalAuthenticators": total,
        "activeAuthenticatorCount": active_count,
        "inactiveAuthenticatorTypes": inactive_types,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if active_count > 0:
        pass_reasons.append(
            f"{active_count} of {total} authenticators are ACTIVE and allowed for enrollment: {', '.join(active_types)}."
        )
    else:
        fail_reasons.append(
            f"No ACTIVE authenticators found among {total} configured authenticators; no auth types are currently allowed."
        )
        recommendations.append(
            "Activate at least one strong authenticator (e.g. okta_verify, webauthn) in the Okta Admin Console under Security > Authenticators."
        )

    if inactive_types:
        recommendations.append(
            f"Consider reviewing inactive authenticators ({', '.join(inactive_types)}) to determine if they should be enabled."
        )

    input_summary = {
        "totalAuthenticators": total,
        "activeAuthenticatorCount": active_count,
        "activeAuthenticatorTypes": active_types,
        "inactiveAuthenticatorTypes": inactive_types,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "authTypesAllowed",
            "vendor": "Okta Adaptive Multi Factor Authentication",
            "category": "iam",
        },
    )
