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
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or data.get("apiResponse") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    approved_count = 0
    pending_count = 0
    rejected_count = 0
    other_status_count = 0
    communicating_count = 0

    for d in devices:
        if not isinstance(d, dict):
            continue
        status = d.get("approvalStatus") or ""
        if status == "APPROVED":
            approved_count = approved_count + 1
        elif status == "PENDING":
            pending_count = pending_count + 1
        elif status == "REJECTED":
            rejected_count = rejected_count + 1
        else:
            other_status_count = other_status_count + 1
        if d.get("offline") is False:
            communicating_count = communicating_count + 1

    is_agent_deployed = total_devices > 0 and approved_count == total_devices

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append("No device records were returned by getDevicesDetailed; agent deployment cannot be confirmed.")
        recommendations.append("Verify the NinjaOne integration credentials and confirm devices are enrolled in the tenant.")
    elif is_agent_deployed:
        pass_reasons.append(
            f"All {total_devices} devices report approvalStatus=APPROVED (agent installed), with {communicating_count} of {total_devices} currently communicating (offline=false)."
        )
    else:
        fail_reasons.append(
            f"Only {approved_count} of {total_devices} devices report approvalStatus=APPROVED; {pending_count} PENDING and {rejected_count} REJECTED devices indicate the agent is not fully deployed/approved fleet-wide."
        )
        recommendations.append("Approve pending devices in the NinjaOne console and investigate rejected devices to ensure the management agent is active fleet-wide.")

    result = {
        "isAgentDeployed": is_agent_deployed,
        "totalDevices": total_devices,
        "approvedDevices": approved_count,
        "pendingDevices": pending_count,
        "rejectedDevices": rejected_count,
        "communicatingDevices": communicating_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "approvedDevices": approved_count},
        metadata={
            "transformationId": "isAgentDeployed",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
