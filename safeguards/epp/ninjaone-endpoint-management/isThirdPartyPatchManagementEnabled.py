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

    status_counts = {}
    devices_with_installs = {}
    failed_count = 0

    for row in results:
        if not isinstance(row, dict):
            continue
        status = row.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "FAILED":
            failed_count = failed_count + 1
        device_id = row.get("deviceId")
        if device_id is not None:
            devices_with_installs[device_id] = True

    distinct_devices = len(devices_with_installs)
    is_enabled = total_installs > 0

    if is_enabled:
        pass_reasons = [
            (
                f"Software Patch history report shows {total_installs} third-party "
                f"patch install records across {distinct_devices} distinct devices "
                f"(deviceId field), confirming third-party patch management is active."
            )
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "The Software Patch history report (getSoftwarePatchInstalls) returned zero "
            "install records, indicating no evidence of active third-party patch management."
        ]
        recommendations = [
            "Enable a Patch Policy with third-party/software patching turned on for at least "
            "one organization, and confirm software patch installs are being recorded."
        ]

    result = {
        "isThirdPartyPatchManagementEnabled": is_enabled,
        "totalSoftwarePatchInstalls": total_installs,
        "distinctDevicesWithInstalls": distinct_devices,
        "failedInstallCount": failed_count,
    }

    input_summary = {
        "totalSoftwarePatchInstalls": total_installs,
        "distinctDevicesWithInstalls": distinct_devices,
        "statusCounts": status_counts,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThirdPartyPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
