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

    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    total_installs = len(results)

    device_ids = set()
    status_counts = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        dev_id = row.get("deviceId")
        if dev_id is not None:
            device_ids.add(dev_id)
        status = row.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1

    distinct_devices = len(device_ids)
    is_enabled = total_installs > 0

    input_summary = {
        "totalInstallRecords": total_installs,
        "distinctDevicesWithInstalls": distinct_devices,
        "statusCounts": status_counts,
    }

    if is_enabled:
        pass_reasons = [
            f"OS patch install history contains {total_installs} install record(s) across {distinct_devices} distinct device(s), indicating OS patch management is actively running (status breakdown: {status_counts})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No OS patch install records were found in the os-patch-installs report (results array is empty), indicating OS patch management is not actively installing patches on any device."
        ]
        recommendations = [
            "Enable and assign an OS patching policy to devices in NinjaOne (Administration -> Policies -> Patching -> Status toggle) so patch installs are recorded."
        ]

    result = {
        "isPatchManagementEnabled": is_enabled,
        "totalInstallRecords": total_installs,
        "distinctDevicesWithInstalls": distinct_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
