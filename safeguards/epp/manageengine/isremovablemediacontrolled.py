"""
Transformation: isRemovableMediaControlled
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether device control policies are configured to monitor/block removable media.
Source: GET /api/1.4/reports/dcm/devicesummary
"""
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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRemovableMediaControlled", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if device control is active from device summary reports."""
    try:
        # Device summary may return device counts by type and status
        devices = []
        if isinstance(data, list):
            devices = data
        elif isinstance(data, dict):
            devices = (
                data.get("devices", []) or
                data.get("device_summary", []) or
                data.get("deviceSummary", []) or
                data.get("data", []) or
                data.get("results", []) or
                []
            )

        if not isinstance(devices, list):
            devices = [devices] if devices else []

        total_devices = len(devices)
        blocked_count = 0
        monitored_count = 0

        for device in devices:
            if not isinstance(device, dict):
                continue

            status = str(device.get("status", device.get("device_status", device.get("action", "")))).lower()
            device_type = str(device.get("device_type", device.get("deviceType", device.get("type", "")))).lower()

            if status in ("blocked", "denied", "restricted", "block"):
                blocked_count = blocked_count + 1
            elif status in ("monitored", "audit", "allowed", "read_only", "readonly"):
                monitored_count = monitored_count + 1

        # Also check for aggregate summary fields
        if not total_devices:
            total_devices = int(data.get("total_devices", data.get("totalDevices", 0)))
            blocked_count = int(data.get("blocked_devices", data.get("blockedDevices", data.get("blocked", 0))))
            monitored_count = int(data.get("monitored_devices", data.get("monitoredDevices", data.get("monitored", 0))))

        # Check if device control module is enabled
        dcm_enabled = data.get("dcm_enabled", data.get("deviceControlEnabled", data.get("enabled", None)))
        if dcm_enabled is not None:
            if isinstance(dcm_enabled, bool):
                is_controlled = dcm_enabled
            else:
                is_controlled = str(dcm_enabled).lower() in ("true", "1", "enabled")
        else:
            # Device control is considered active if any devices are being tracked/blocked
            is_controlled = (blocked_count > 0) or (monitored_count > 0) or (total_devices > 0)

        return {
            "isRemovableMediaControlled": is_controlled,
            "totalDevices": total_devices,
            "blockedDevices": blocked_count,
            "monitoredDevices": monitored_count
        }
    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRemovableMediaControlled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Device control is active in ManageEngine Endpoint Central")
            if extra_fields.get("blockedDevices"):
                pass_reasons.append(f"{extra_fields['blockedDevices']} devices blocked")
            if extra_fields.get("monitoredDevices"):
                pass_reasons.append(f"{extra_fields['monitoredDevices']} devices monitored")
            if extra_fields.get("totalDevices"):
                pass_reasons.append(f"{extra_fields['totalDevices']} total devices tracked")
        else:
            fail_reasons.append("No device control activity detected in Endpoint Central")
            recommendations.append("Enable Device Control module in Endpoint Central to manage removable media")
            recommendations.append("Configure device control policies to block or audit USB and removable storage devices")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
