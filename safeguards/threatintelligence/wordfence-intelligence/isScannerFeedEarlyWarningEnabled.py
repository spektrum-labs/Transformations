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

    expected_keys = ["id", "title", "software", "references", "copyrights"]

    if isinstance(data, dict):
        present_keys = [k for k in expected_keys if k in data and isinstance(data.get(k), list)]
        entry_count = 0
        ids = data.get("id")
        if isinstance(ids, list):
            entry_count = len(ids)
    else:
        present_keys = []
        entry_count = 0
        api_errors.append("Scanner feed response root was not a dict envelope as documented")

    schema_intact = len(present_keys) == len(expected_keys)

    is_enabled = schema_intact

    input_summary = {
        "expectedKeys": expected_keys,
        "presentKeys": present_keys,
        "entryCount": entry_count,
    }

    if is_enabled:
        pass_reasons = [
            f"getVulnerabilityScannerFeed responded HTTP 200 with the documented early-warning "
            f"schema fields present: {', '.join(present_keys)}.",
            f"Scanner feed currently lists {entry_count} vulnerability entr{'y' if entry_count == 1 else 'ies'} "
            "under active research, confirming the distinct low-latency feed is reachable and structured "
            "independently of the Production Feed.",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"getVulnerabilityScannerFeed response did not contain the full documented schema. "
            f"Present keys: {present_keys}; expected: {expected_keys}."
        ]
        recommendations = [
            "Verify the apiToken has access to the Wordfence Intelligence V3 Scanner Feed and that the "
            "endpoint https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner is reachable."
        ]

    result = {
        "isScannerFeedEarlyWarningEnabled": is_enabled,
        "scannerFeedEntryCount": entry_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isScannerFeedEarlyWarningEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
        api_errors=api_errors,
        transformation_errors=transformation_errors,
    )
