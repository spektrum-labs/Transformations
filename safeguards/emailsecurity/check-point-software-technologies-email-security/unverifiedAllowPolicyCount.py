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

    api_errors = []
    if data.get("error") or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        api_errors.append(
            f"Vendor API returned an error: {data.get('message') or data.get('errorMessage') or 'unknown error'}"
        )

    response_data = data.get("responseData") or []
    if not isinstance(response_data, list):
        response_data = []

    response_envelope = data.get("responseEnvelope") or {}
    if not isinstance(response_envelope, dict):
        response_envelope = {}

    unverified_count = 0
    verified_count = 0
    for item in response_data:
        if not isinstance(item, dict):
            continue
        is_verified = False
        if item.get("verified") is True:
            is_verified = True
        if item.get("reVerified") is True:
            is_verified = True
        if item.get("lastVerifiedDate"):
            is_verified = True
        if item.get("lastReviewedDate"):
            is_verified = True
        if item.get("reviewStatus") == "reviewed":
            is_verified = True
        if is_verified:
            verified_count = verified_count + 1
        else:
            unverified_count = unverified_count + 1

    total_exceptions = len(response_data)

    input_summary = {
        "totalExceptions": total_exceptions,
        "unverifiedCount": unverified_count,
        "verifiedCount": verified_count,
        "totalRecordsNumber": response_envelope.get("totalRecordsNumber"),
    }

    if api_errors:
        return create_response(
            result={"unverifiedAllowPolicyCount": 0},
            validation=validation,
            fail_reasons=[
                "Could not retrieve anti-malware/allow-list exception data because the vendor API call failed authentication or returned an error."
            ],
            recommendations=[
                "Verify the API credentials (clientId/accessKey) configured for this integration have access to the sectool-exceptions endpoint."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "unverifiedAllowPolicyCount", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
            api_errors=api_errors,
        )

    if total_exceptions == 0:
        return create_response(
            result={"unverifiedAllowPolicyCount": 0},
            validation=validation,
            pass_reasons=[
                "No sender/URL allow-list exceptions were returned by getAntiMalwareExceptions, so there are zero unverified allow-list entries."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "unverifiedAllowPolicyCount", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    if unverified_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{unverified_count} of {total_exceptions} allow-list exception entries have no verified/reVerified/lastVerifiedDate/lastReviewedDate field set, indicating they were never re-reviewed since creation."
        ]
        recommendations = [
            "Review and re-verify outstanding sender/URL allow-list exceptions and record a verification or review date/flag for each."
        ]
    else:
        pass_reasons = [
            f"All {total_exceptions} allow-list exception entries carry a verified/reVerified/lastVerifiedDate/lastReviewedDate marker."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={"unverifiedAllowPolicyCount": unverified_count},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "unverifiedAllowPolicyCount", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
    )
