
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
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
        if not isinstance(results, list):
            results = []
    else:
        results = []

    total = len(results)
    failed_count = 0
    installed_count = 0
    other_statuses = {}

    for rec in results:
        if not isinstance(rec, dict):
            continue
        status = rec.get("status")
        if status == "FAILED":
            failed_count = failed_count + 1
        elif status == "INSTALLED":
            installed_count = installed_count + 1
        else:
            key = status if status else "UNKNOWN"
            other_statuses[key] = other_statuses.get(key, 0) + 1

    FAILURE_THRESHOLD_PCT = 5.0

    if total == 0:
        is_valid = False
        failure_rate = 0.0
        fail_reasons = [
            "No OS patch installation records were returned by getOSPatchInstallsReport, "
            "so patch installation activity cannot be confirmed as executing successfully."
        ]
        pass_reasons = []
        recommendations = [
            "Verify that devices are checking in and reporting patch installation activity to NinjaOne."
        ]
    else:
        failure_rate = (failed_count / total) * 100.0
        if failure_rate < FAILURE_THRESHOLD_PCT:
            is_valid = True
            pass_reasons = [
                f"Of {total} OS patch installation records, {installed_count} report status=INSTALLED "
                f"and only {failed_count} report status=FAILED ({failure_rate:.2f}% failure rate), "
                f"below the {FAILURE_THRESHOLD_PCT}% threshold indicating patch management is executing successfully."
            ]
            fail_reasons = []
            recommendations = []
        else:
            is_valid = False
            pass_reasons = []
            fail_reasons = [
                f"Of {total} OS patch installation records, {failed_count} report status=FAILED "
                f"({failure_rate:.2f}% failure rate), exceeding the {FAILURE_THRESHOLD_PCT}% threshold, "
                f"indicating patch installation is stuck or erroring on the fleet."
            ]
            recommendations = [
                "Investigate devices with FAILED patch installation status and re-run patch scans/installs.",
                "Check device connectivity and disk space, which commonly cause patch install failures."
            ]

    result = {
        "isPatchManagementValid": is_valid,
        "totalPatchInstallRecords": total,
        "failedPatchInstallCount": failed_count,
        "installedPatchInstallCount": installed_count,
        "failureRatePercentage": round(failure_rate, 2),
    }

    input_summary = {
        "totalRecords": total,
        "installedCount": installed_count,
        "failedCount": failed_count,
        "otherStatusCounts": other_statuses,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchManagementValid",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
