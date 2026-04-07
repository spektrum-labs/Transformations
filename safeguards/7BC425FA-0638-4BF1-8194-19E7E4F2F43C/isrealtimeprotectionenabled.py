"""
Transformation: isRealTimeProtectionEnabled
Vendor: Microsoft Defender for Endpoint  |  Category: Endpoint Security
Evaluates: Whether real-time protection is active across all devices

Data source: Advanced Hunting API (POST /api/advancedqueries/run)
Query: DeviceTvmSecureConfigurationAssessment
       | where ConfigurationId == 'scid-2011'
       | project DeviceId, DeviceName, ConfigurationId, IsCompliant, IsApplicable
Permission: AdvancedQuery.Read.All

scid-2011 = "Turn on real-time protection" configuration check.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRealTimeProtectionEnabled", "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"}
        }
    }


def to_bool(val):
    """Convert various truthy representations to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


def extract_devices(data):
    """Extract device records from Advanced Hunting or legacy response formats."""
    if isinstance(data, dict):
        if "Results" in data:
            results = data["Results"]
            return results if isinstance(results, list) else []
        if "value" in data:
            value = data["value"]
            return value if isinstance(value, list) else []
        return [data]
    if isinstance(data, list):
        return data
    return []


def evaluate(data):
    """Evaluate real-time protection across all devices.

    Supports two response formats:
    1. Advanced Hunting (scid-2011): IsCompliant field per device
    2. Legacy machines API: avMode field per device
    """
    try:
        devices = extract_devices(data)

        if not devices:
            return {"isRealTimeProtectionEnabled": False, "error": "No devices found"}

        total = 0
        protected = 0
        non_compliant_devices = []

        for device in devices:
            if not isinstance(device, dict):
                continue

            device_name = device.get("DeviceName") or device.get("computerDnsName") or "Unknown"

            # Advanced Hunting format (scid-2011): IsCompliant
            if "IsCompliant" in device:
                is_applicable = to_bool(device.get("IsApplicable", True))
                if not is_applicable:
                    continue
                total += 1
                if to_bool(device.get("IsCompliant", False)):
                    protected += 1
                else:
                    non_compliant_devices.append(device_name)
            # Legacy machines API format: avMode
            elif "avMode" in device:
                total += 1
                if device.get("avMode", "") in ("Active", "active", "SensorEnabled"):
                    protected += 1
                else:
                    non_compliant_devices.append(device_name)
            else:
                continue

        if total == 0:
            return {"isRealTimeProtectionEnabled": False, "error": "No applicable devices found with real-time protection data"}

        score = round((protected / total) * 100, 2)

        return {
            "isRealTimeProtectionEnabled": protected > 0,
            "scoreInPercentage": score,
            "totalDevices": total,
            "realTimeProtectedCount": protected,
            "nonCompliantDevices": non_compliant_devices[:20]
        }
    except Exception as e:
        return {"isRealTimeProtectionEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRealTimeProtectionEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable real-time protection on all devices via Microsoft Defender for Endpoint")

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
