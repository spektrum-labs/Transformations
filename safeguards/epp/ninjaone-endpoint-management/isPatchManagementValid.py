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


FAILURE_STATUS_VALUES = ["FAILED", "FAILURE", "ERROR"]
FAILURE_RATE_THRESHOLD = 0.10


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    total = len(results)
    failed = 0
    for row in results:
        if not isinstance(row, dict):
            continue
        status = row.get("status") or ""
        status_upper = status.upper() if isinstance(status, str) else ""
        if status_upper in FAILURE_STATUS_VALUES:
            failed = failed + 1

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        is_valid = True
        pass_reasons.append(
            "No os-patch-installs records were returned for the queried window, "
            "so no scan/install failures were observed for this device."
        )
        failure_rate = 0.0
    else:
        failure_rate = failed / total
        if failure_rate <= FAILURE_RATE_THRESHOLD:
            is_valid = True
            pass_reasons.append(
                f"Of {total} os-patch-install records, {failed} reported a failure status "
                f"({FAILURE_STATUS_VALUES}), a failure rate of {round(failure_rate * 100, 1)}%, "
                f"which is within the {int(FAILURE_RATE_THRESHOLD * 100)}% acceptable threshold."
            )
        else:
            is_valid = False
            fail_reasons.append(
                f"Of {total} os-patch-install records, {failed} reported a failure status "
                f"({FAILURE_STATUS_VALUES}), a failure rate of {round(failure_rate * 100, 1)}%, "
                f"exceeding the {int(FAILURE_RATE_THRESHOLD * 100)}% acceptable threshold."
            )
            recommendations.append(
                "Investigate devices with FAILED os-patch-install status in NinjaOne "
                "(Patching > OS Patches report) and re-run or repair the patch scan/install agent."
            )

    result = {
        "isPatchManagementValid": is_valid,
        "totalPatchInstallRecords": total,
        "failedPatchInstallRecords": failed,
        "failureRate": round(failure_rate * 100, 2),
    }

    input_summary = {
        "totalPatchInstallRecords": total,
        "failedPatchInstallRecords": failed,
        "failureRatePercent": round(failure_rate * 100, 2),
    }

    metadata = {
        "transformationId": "isPatchManagementValid",
        "vendor": "NinjaOne Endpoint Management",
        "category": "epp",
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
