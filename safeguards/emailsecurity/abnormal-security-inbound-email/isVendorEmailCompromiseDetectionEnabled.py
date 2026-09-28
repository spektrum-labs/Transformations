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
        vendor_cases = data
    elif isinstance(data, dict):
        vendor_cases = data.get("vendorCases") or data.get("data") or []
    else:
        vendor_cases = []

    case_count = len(vendor_cases) if isinstance(vendor_cases, list) else 0
    is_enabled = case_count > 0

    sample_ids = []
    if isinstance(vendor_cases, list):
        for case in vendor_cases[:5]:
            if isinstance(case, dict) and case.get("vendorCaseId") is not None:
                sample_ids.append(case.get("vendorCaseId"))

    if is_enabled:
        pass_reasons = [
            f"Found {case_count} Vendor Email Compromise (VEC) case record(s) via /v1/vendor-cases "
            f"(sample vendorCaseId values: {sample_ids}). Vendor cases are generated exclusively by "
            "Abnormal's VEC detection module, so their presence evidences the capability is enabled."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No vendor case records were returned from /v1/vendor-cases, so there is no evidence "
            "that Vendor Email Compromise (VEC) detection has produced any detections for this tenant."
        ]
        recommendations = [
            "Confirm Vendor Email Compromise detection is licensed and enabled in the Abnormal Security "
            "console, and verify the API token has access to the vendor-cases resource."
        ]

    result = {
        "isVendorEmailCompromiseDetectionEnabled": is_enabled,
        "vendorCaseCount": case_count,
    }

    input_summary = {"vendorCaseCount": case_count}

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isVendorEmailCompromiseDetectionEnabled",
            "vendor": "Abnormal Security Inbound Email",
            "category": "emailsecurity",
        },
    )
