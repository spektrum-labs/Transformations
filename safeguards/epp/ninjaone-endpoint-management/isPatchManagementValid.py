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
    else:
        results = []

    if not isinstance(results, list):
        results = []

    failed_statuses = ["FAILED", "REJECTED"]
    total = len(results)
    failed = 0
    failed_kbs = []
    for item in results:
        if not isinstance(item, dict):
            continue
        status = item.get("status") or ""
        status_upper = status.upper() if isinstance(status, str) else ""
        if status_upper in failed_statuses:
            failed = failed + 1
            kb = item.get("kbNumber") or item.get("name") or item.get("id")
            if kb is not None and len(failed_kbs) < 5:
                failed_kbs.append(str(kb))

    if total == 0:
        is_valid = True
        pass_reasons = [
            "No pending/failed/rejected OS patch records were returned by getOSPatchesReport, "
            "indicating no active patch failures across the fleet."
        ]
        fail_reasons = []
        recommendations = []
    else:
        failure_rate = float(failed) / float(total)
        is_valid = failed == 0
        if is_valid:
            pass_reasons = [
                "All %d tracked OS patch records report a non-failed status (0 FAILED/REJECTED entries), "
                "indicating patch management is executing successfully." % total
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "%d of %d tracked OS patch records (%.1f%%) report status FAILED or REJECTED (examples: %s), "
                "indicating patch installation is not completing successfully."
                % (failed, total, failure_rate * 100.0, ", ".join(failed_kbs))
            ]
            recommendations = [
                "Investigate devices with FAILED/REJECTED OS patch installs and re-run patch scans/deployments "
                "to restore successful patch management."
            ]

    result = {
        "isPatchManagementValid": is_valid,
        "totalTrackedPatches": total,
        "failedOrRejectedPatches": failed,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalTrackedPatches": total, "failedOrRejectedPatches": failed},
        metadata={
            "transformationId": "isPatchManagementValid",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
