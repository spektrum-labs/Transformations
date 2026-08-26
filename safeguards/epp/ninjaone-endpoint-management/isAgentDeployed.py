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

    data = data if isinstance(data, (dict, list)) else []

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or data.get("items") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = 0
    approved_devices = 0
    online_devices = 0
    approved_and_online = 0

    for device in devices:
        if not isinstance(device, dict):
            continue
        total_devices = total_devices + 1
        approval_status = device.get("approvalStatus")
        offline_flag = device.get("offline")
        is_approved = approval_status == "APPROVED"
        is_online = offline_flag is False
        if is_approved:
            approved_devices = approved_devices + 1
        if is_online:
            online_devices = online_devices + 1
        if is_approved and is_online:
            approved_and_online = approved_and_online + 1

    is_agent_deployed = approved_and_online > 0

    input_summary = {
        "totalDevices": total_devices,
        "approvedDevices": approved_devices,
        "onlineDevices": online_devices,
        "approvedAndOnlineDevices": approved_and_online,
    }

    if is_agent_deployed:
        pass_reasons = [
            (
                "%d of %d devices returned by getDevicesDetailed have approvalStatus='APPROVED' "
                "and offline=false, confirming the NinjaOne management agent is installed and "
                "actively communicating on at least one endpoint."
            )
            % (approved_and_online, total_devices)
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_devices == 0:
            fail_reasons = [
                "getDevicesDetailed returned no device records, so no evidence of an installed "
                "and communicating NinjaOne agent was found."
            ]
        else:
            fail_reasons = [
                (
                    "Of %d devices returned by getDevicesDetailed, none had both "
                    "approvalStatus='APPROVED' and offline=false (approved=%d, online=%d), "
                    "so no device could be confirmed as actively running and communicating "
                    "the NinjaOne agent."
                )
                % (total_devices, approved_devices, online_devices)
            ]
        recommendations = [
            "Verify the NinjaOne agent installer has been deployed to endpoints and that "
            "devices are approved in the NinjaOne console (Administration > Approvals) and "
            "have network connectivity to check in."
        ]

    result = {
        "isAgentDeployed": is_agent_deployed,
        "totalDevices": total_devices,
        "approvedDevices": approved_devices,
        "onlineDevices": online_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAgentDeployed",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
