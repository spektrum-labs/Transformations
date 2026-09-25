"""Transformation: isEPPLoggingEnabled (CrowdStrike Falcon)"""
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
        devices = data.get("resources") or data.get("data") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total = len(devices)
    full_logging = []
    rfm_devices = []

    for d in devices:
        if not isinstance(d, dict):
            continue
        rfm = d.get("reduced_functionality_mode")
        rfm_str = str(rfm).strip().lower() if rfm is not None else ""
        hostname = d.get("hostname") or d.get("device_id") or "unknown"
        if rfm_str in ("no", "false", "0"):
            full_logging.append(hostname)
        else:
            rfm_devices.append(hostname)

    is_enabled = (len(full_logging) > 0) and (len(rfm_devices) == 0)

    result = {
        "isEPPLoggingEnabled": is_enabled,
        "totalDevicesEvaluated": total,
        "devicesWithFullLogging": len(full_logging),
        "devicesInReducedFunctionalityMode": len(rfm_devices),
    }

    if total == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No device records were present in the getDeviceDetails response, so reduced_functionality_mode could not be inspected on any host and sensor telemetry/logging status could not be confirmed."],
            recommendations=["Verify that devices/entities/devices/v2 returns enrolled hosts and re-run the check."],
            input_summary={"totalDevicesEvaluated": 0},
            metadata={"transformationId": "isEPPLoggingEnabled", "vendor": "CrowdStrike Falcon", "category": "epp"},
        )

    if is_enabled:
        pass_reasons = [
            f"All {total} evaluated device(s) report reduced_functionality_mode='no' (sample hosts: {', '.join(full_logging[:5])}), confirming the Falcon sensor is operating with full telemetry/prevention capability and streaming events off-platform via the Event Streams API."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{len(rfm_devices)} of {total} evaluated device(s) report reduced_functionality_mode not equal to 'no' (sample affected hosts: {', '.join(rfm_devices[:5])}), meaning the sensor is running in a degraded mode where full event telemetry/logging upload is not guaranteed."
        ]
        recommendations = [
            "Investigate why the affected hosts are in Reduced Functionality Mode (commonly caused by license/registration or driver issues) and restore full sensor functionality so prevention/detection events continue to stream to the Event Streams API/SIEM."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevicesEvaluated": total, "devicesWithFullLogging": len(full_logging)},
        metadata={"transformationId": "isEPPLoggingEnabled", "vendor": "CrowdStrike Falcon", "category": "epp"},
    )
