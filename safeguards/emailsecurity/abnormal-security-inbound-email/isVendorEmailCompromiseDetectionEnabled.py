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


KEY = "isVendorEmailCompromiseDetectionEnabled"


def not_measured(reason, validation):
    """No verdict: the result is None and the data-collection status is error, so the evaluator
    shows Not evaluated instead of a failed check. The reason is fixed text: the vendor's own error
    message is never copied into it."""
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[reason],
        api_errors=[reason],
        metadata={"transformationId": KEY, "vendor": "Abnormal Security Inbound Email", "category": "emailsecurity"},
    )


def is_error_body(data):
    return isinstance(data, dict) and (data.get("error") is True or bool(data.get("errors")))


def objects_only(items, noun):
    """(objects, problem): the object items of a list.

    A non-empty list with no object in it proves nothing, so it is "not measured". Items that are not
    objects are never counted as records. An empty list is passed through unchanged."""
    objects = [x for x in items if isinstance(x, dict)]
    if items and not objects:
        return None, "Abnormal returned a " + noun + " list with no objects in it; nothing to measure."
    return objects, None


def vendor_cases_of(data):
    """(cases, problem): the case list of a /v1/vendor-cases body, or why there is none.

    An empty list from a well-formed response is still read as "no cases" (unchanged); only an
    error, an empty or an unrecognised body is "not measured"."""
    if isinstance(data, list):
        return data, None
    if is_error_body(data):
        return None, "Abnormal returned an error for the vendor cases; nothing to measure."
    if isinstance(data, dict):
        for name in ["vendorCases", "data"]:
            if isinstance(data.get(name), list):
                return data.get(name), None
    return None, "Abnormal returned no vendor case list; nothing to measure."


def case_id(item):
    """The vendorCaseId of a real vendor case record, or None.

    A real record is an object that carries its own case id: a non-empty string or a number. An error
    object, an empty object or an object without an id is not a case."""
    if not isinstance(item, dict):
        return None
    value = item.get("vendorCaseId")
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, (int, float)):
        # NaN and Infinity (a JSON body can carry them) are numbers but not case ids.
        if value == value and abs(value) != float("inf"):
            return value
    return None


def validation_failed(validation):
    """True when the input validation says the body is not the expected shape."""
    status = validation.get("status") if isinstance(validation, dict) else None
    return isinstance(status, str) and status.strip().lower() in ["failed", "error"]


def has_next_page(data):
    """True when the body says another page of cases follows."""
    if not isinstance(data, dict):
        return False
    for name in ["nextPageNumber", "nextPageToken"]:
        token = data.get(name)
        if token is not None and token is not False and token != "":
            return True
    return False


def transform(input):
    data, validation = extract_input(input)
    if not isinstance(validation, dict):
        validation = {"status": "unknown", "errors": [], "warnings": []}
    if validation_failed(validation):
        return not_measured("Abnormal's vendor cases failed input validation; nothing to measure.", validation)
    vendor_cases, problem = vendor_cases_of(data)
    if problem is None:
        vendor_cases, problem = objects_only(vendor_cases, "vendor case")
    if problem is None and vendor_cases:
        vendor_cases = [case for case in vendor_cases if case_id(case) is not None]
        if not vendor_cases:
            problem = "Abnormal returned a vendor case list with no case record (vendorCaseId) in it; nothing to measure."
    if problem is None and not vendor_cases and has_next_page(data):
        problem = "Abnormal returned an empty first page of vendor cases and says another page follows; nothing to measure."
    if problem is not None:
        return not_measured(problem, validation)

    case_count = len(vendor_cases)
    is_enabled = case_count > 0

    sample_ids = [case_id(case) for case in vendor_cases[:5]]

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
