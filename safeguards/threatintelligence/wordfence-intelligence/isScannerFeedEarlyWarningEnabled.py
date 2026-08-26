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

    transformation_errors = []
    expected_keys = ["id", "title", "software", "informational"]

    if isinstance(data, list):
        # Array-root response: treat list itself as entries
        entries = data
        has_expected_shape = True
        entry_count = len(entries)
        shape_label = "list"
    elif isinstance(data, dict):
        # Columnar shape observed from vendor: parallel arrays keyed by field name
        present_keys = [k for k in expected_keys if k in data]
        has_expected_shape = len(present_keys) > 0
        id_list = data.get("id")
        if isinstance(id_list, list):
            entry_count = len(id_list)
        else:
            items = data.get("data") or data.get("results") or []
            entry_count = len(items) if isinstance(items, list) else 0
        shape_label = "dict"
    else:
        has_expected_shape = False
        entry_count = 0
        shape_label = "other"

    is_enabled = bool(has_expected_shape)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            "The scanner feed endpoint (/api/intelligence/v3/vulnerabilities/scanner) "
            "returned HTTP 200 with the expected early-warning schema keys "
            f"({', '.join(expected_keys)}), confirming the distinct low-latency scanner "
            f"feed is enabled and reachable. It currently reports {entry_count} "
            "actively-researched vulnerability entries."
        )
    else:
        fail_reasons.append(
            "The scanner feed response did not contain the expected early-warning "
            f"schema keys ({', '.join(expected_keys)}); response shape was "
            f"'{shape_label}', so the distinct scanner feed could not be confirmed as enabled."
        )
        recommendations.append(
            "Verify the Wordfence Intelligence API token has access to the v3 scanner "
            "feed endpoint and that the endpoint returns the documented id/title/software/informational schema."
        )

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
        input_summary={"entryCount": entry_count, "hasExpectedShape": has_expected_shape},
        metadata={
            "transformationId": "isScannerFeedEarlyWarningEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
        transformation_errors=transformation_errors,
    )
