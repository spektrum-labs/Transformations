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

    api_errors = []
    transformation_errors = []

    # This endpoint (GET /admin/v1/users/{user_id}/webauthncredentials) is the
    # documented Duo Admin API surface for managing a user's FIDO/WebAuthn
    # authenticators. A successful, well-formed call (stat == OK, a
    # "response" list present, whether or not it is populated) demonstrates
    # that this integration has API access to manage FIDO authenticators.
    stat = None
    has_response_key = False
    total_objects = None

    if isinstance(data, dict):
        stat = data.get("stat")
        has_response_key = "response" in data
        metadata = data.get("metadata") or {}
        if isinstance(metadata, dict):
            total_objects = metadata.get("total_objects")
        response_list = data.get("response")
        if not isinstance(response_list, list):
            response_list = []
    elif isinstance(data, list):
        response_list = data
        has_response_key = True
    else:
        response_list = []
        api_errors.append("Unrecognized response shape for getUserWebauthncredentials")

    has_access = bool(stat == "OK" or has_response_key)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_access:
        pass_reasons.append(
            f"Duo Admin API call to /admin/v1/users/{{user_id}}/webauthncredentials succeeded "
            f"(stat={stat!r}, response key present={has_response_key}, "
            f"total_objects={total_objects}, credentials_returned={len(response_list)}). "
            f"This confirms API access to the WebAuthn (FIDO2) authenticator management endpoint."
        )
    else:
        fail_reasons.append(
            f"Call to the WebAuthn credential management endpoint did not return a recognizable "
            f"success envelope (stat={stat!r}, response key present={has_response_key})."
        )
        recommendations.append(
            "Verify the integration credential has permission to call "
            "/admin/v1/users/{user_id}/webauthncredentials and that the endpoint is reachable."
        )

    input_summary = {
        "stat": stat,
        "hasResponseKey": has_response_key,
        "totalObjects": total_objects,
        "credentialsReturned": len(response_list),
    }

    result = {
        "hasFIDOAuthenticatorManagementAPIAccess": has_access,
        "credentialsReturned": len(response_list),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasFIDOAuthenticatorManagementAPIAccess",
            "vendor": "Duo",
            "category": "iam",
        },
        transformation_errors=transformation_errors,
        api_errors=api_errors,
    )
