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

    is_error = bool(data.get("error"))
    status_code = data.get("statusCode")
    error_type = data.get("errorType")
    error_message = data.get("errorMessage") or data.get("message")

    token_data = data.get("data") if isinstance(data.get("data"), dict) else {}
    token = token_data.get("token")
    csrf = token_data.get("csrf")
    expires_in = token_data.get("expiresIn")
    success_flag = data.get("success")

    input_summary = {
        "success": success_flag,
        "error": is_error,
        "statusCode": status_code,
        "errorType": error_type,
        "hasToken": bool(token),
        "hasExpiresIn": expires_in is not None,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    is_managed = False

    if token and expires_in is not None:
        is_managed = True
        pass_reasons.append(
            "auth/external token exchange returned a short-lived bearer token "
            "(expiresIn=%s seconds) plus a csrf value, confirming the tenant uses "
            "a rotatable OAuth client-credential exchange (clientId/clientSecret -> "
            "scoped token) rather than a static shared API key." % (expires_in,)
        )
    elif is_error and error_type == "authentication":
        is_managed = False
        fail_reasons.append(
            "Call to the auth/external token endpoint failed with statusCode=%s, "
            "errorType='%s', message='%s'. Could not confirm that the configured "
            "clientId/clientSecret pair successfully exchanges for a scoped, "
            "time-limited token; the credential architecture (scoped OAuth client "
            "credentials per the vendor profile) could not be verified live against "
            "this tenant." % (status_code, error_type, error_message)
        )
        recommendations.append(
            "Verify the clientId and clientSecret settings are current, valid "
            "Infinity Portal Account API Key credentials scoped to the Email & "
            "Collaboration service, and re-run the token exchange to confirm a "
            "rotatable scoped token (data.token/expiresIn) is issued."
        )
    else:
        is_managed = False
        fail_reasons.append(
            "auth/external response did not contain a data.token/expiresIn pair "
            "(response keys: %s), so a scoped rotatable token issuance could not "
            "be confirmed." % (", ".join(sorted(data.keys())) or "none",)
        )
        recommendations.append(
            "Confirm the tenant's Infinity Portal Account API Key (clientId/"
            "clientSecret) is configured and that the token endpoint returns a "
            "scoped, expiring bearer token."
        )

    result = {
        "isScopedAPIAuthTokenManaged": is_managed,
        "hasToken": bool(token),
        "tokenExpiresInSeconds": expires_in,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isScopedAPIAuthTokenManaged",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
