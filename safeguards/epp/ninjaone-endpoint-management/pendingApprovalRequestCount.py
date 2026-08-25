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


def get_devices_from_response(data):
    """Normalize the devices-detailed response into a list of device dicts.

    Handles: direct list of device objects, {"data": [...]}/{"items": [...]}/
    {"devices": [...]} wrapper shapes, and a columnar shape where each
    device field is captured as a parallel array (as seen in the tenant
    capture: {"id": [...], "approvalStatus": [...], ...}).
    """
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("data", "items", "devices"):
        v = data.get(key)
        if isinstance(v, list):
            return v
    approval_col = data.get("approvalStatus")
    if isinstance(approval_col, list):
        n = len(approval_col)
        id_col = data.get("id") if isinstance(data.get("id"), list) else []
        rows = []
        for i in range(n):
            rows.append({
                "id": id_col[i] if i < len(id_col) else None,
                "approvalStatus": approval_col[i],
            })
        return rows
    return []


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) or isinstance(data, list) else {}

    devices = get_devices_from_response(data)

    pending_devices = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        status = d.get("approvalStatus")
        if isinstance(status, str) and status.upper() == "PENDING":
            pending_devices.append(d)

    pending_count = len(pending_devices)
    total_devices = len(devices)

    if pending_count > 0:
        sample_ids = [d.get("id") for d in pending_devices[:5]]
        pass_reasons = [
            f"Found {pending_count} device(s) with approvalStatus=PENDING out of {total_devices} devices scanned in this response (sample device ids: {sample_ids})."
        ]
        fail_reasons = []
        recommendations = [
            "Review pending device approval requests in the NinjaOne console and approve or reject them to keep the managed fleet inventory accurate."
        ]
    else:
        pass_reasons = [
            f"No devices with approvalStatus=PENDING were found among the {total_devices} devices scanned in this response."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "pendingApprovalRequestCount": pending_count,
        "totalDevicesScanned": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevicesScanned": total_devices, "pendingApprovalRequestCount": pending_count},
        metadata={
            "transformationId": "pendingApprovalRequestCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
