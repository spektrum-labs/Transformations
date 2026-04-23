"""
Transformation: requiredCoveragePercentage
Vendor: Expel  |  Category: mdr
Evaluates: Calculate MDR coverage by comparing the count of security devices with an
active or healthy connection status against the total number of registered security
devices. Returns a coverage percentage reflecting the proportion of monitored devices
actively reporting into Expel.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Expel", "category": "mdr"}
        }
    }


ACTIVE_STATUSES = ["ok", "active", "healthy", "good", "connected", "online", "running"]


def is_active_status(status_val):
    if status_val is None:
        return False
    return str(status_val).lower() in ACTIVE_STATUSES


def evaluate(data):
    try:
        security_devices = data.get("data", [])
        if not isinstance(security_devices, list):
            security_devices = []

        total_devices = len(security_devices)
        active_devices = 0
        inactive_devices = []
        active_device_names = []

        for device in security_devices:
            if not isinstance(device, dict):
                continue
            attributes = device.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}

            connection_status = attributes.get("connection_status", None)
            status = attributes.get("status", None)
            health = attributes.get("health_status", None)

            effective_status = connection_status or status or health
            name = attributes.get("name", device.get("id", "unknown"))

            if is_active_status(effective_status):
                active_devices = active_devices + 1
                active_device_names.append(str(name))
            else:
                inactive_devices.append({"name": str(name), "status": str(effective_status)})

        if total_devices > 0:
            coverage = (active_devices * 100) / total_devices
        else:
            coverage = 0.0

        coverage_rounded = int(coverage * 100 + 0.5) / 100

        return {
            "requiredCoveragePercentage": coverage_rounded,
            "totalSecurityDevices": total_devices,
            "activeDevices": active_devices,
            "inactiveDeviceCount": len(inactive_devices),
            "activeDeviceNames": active_device_names,
            "inactiveDevices": inactive_devices
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0.0, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: 0.0}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, 0.0)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_devices = eval_result.get("totalSecurityDevices", 0)
        active_count = eval_result.get("activeDevices", 0)
        inactive_count = eval_result.get("inactiveDeviceCount", 0)
        inactive_list = eval_result.get("inactiveDevices", [])
        active_names = eval_result.get("activeDeviceNames", [])

        if total_devices == 0:
            fail_reasons.append("No security devices registered in Expel Workbench. Coverage is 0%.")
            recommendations.append("Register security devices in Expel Workbench to establish MDR monitoring coverage.")
        elif result_value >= 100.0:
            pass_reasons.append("Full MDR coverage: all " + str(total_devices) + " security device(s) are active and reporting.")
        elif result_value > 0.0:
            pass_reasons.append("Partial MDR coverage: " + str(active_count) + " of " + str(total_devices) + " devices active (" + str(result_value) + "%).")
            if inactive_count > 0:
                recommendations.append("Investigate " + str(inactive_count) + " inactive device(s) to restore full MDR coverage.")
        else:
            fail_reasons.append("No active security devices found. Coverage is 0%. All " + str(total_devices) + " registered device(s) are inactive.")
            recommendations.append("Check the connection status of all registered security devices in Expel Workbench.")

        for name in active_names:
            additional_findings.append("Active device: " + str(name))
        for entry in inactive_list:
            additional_findings.append("Inactive device: " + str(entry.get("name", "unknown")) + " (status: " + str(entry.get("status", "unknown")) + ")")

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSecurityDevices": total_devices, "activeDevices": active_count, "coveragePercentage": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
