import json
from datetime import datetime


def extract_input(input_data):
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
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    pending_devices = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        status = d.get("approvalStatus")
        if isinstance(status, str) and status.upper() == "PENDING":
            pending_devices.append(d)

    pending_count = len(pending_devices)

    pending_names = []
    for d in pending_devices[:5]:
        name = d.get("systemName") or d.get("displayName") or str(d.get("id"))
        pending_names.append(name)

    if total_devices == 0:
        fail_reasons = ["No device records were returned by getDevicesDetailed; cannot determine pending approval count."]
        pass_reasons = []
        recommendations = ["Verify the getDevicesDetailed endpoint is returning device inventory data."]
    elif pending_count > 0:
        sample = ", ".join(pending_names)
        pass_reasons = [
            f"Found {pending_count} of {total_devices} devices with approvalStatus=PENDING awaiting technician review (e.g. {sample})."
        ]
        fail_reasons = []
        recommendations = [
            "Review and approve or reject the pending devices in the NinjaOne console to bring them into the managed fleet."
        ]
    else:
        pass_reasons = [
            f"No devices are pending approval; all {total_devices} scanned devices have a non-PENDING approvalStatus."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "pendingApprovalRequestCount": pending_count,
        "totalDevicesScanned": total_devices,
    }

    input_summary = {
        "totalDevicesScanned": total_devices,
        "pendingApprovalRequestCount": pending_count,
    }

    metadata = {
        "transformationId": "pendingApprovalRequestCount",
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
