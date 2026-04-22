"""
Transformation: isMDRConfigured
Vendor: Expel  |  Category: mdr
Evaluates: Verify that at least one security device is registered and active in Expel
Workbench. A non-empty data array in the security_devices response confirms MDR is
configured with at least one monitored security device connected.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMDRConfigured", "vendor": "Expel", "category": "mdr"}
        }
    }


def evaluate(data):
    try:
        security_devices = data.get("data", [])
        if not isinstance(security_devices, list):
            security_devices = []

        total_devices = len(security_devices)
        device_names = []
        device_types = []

        for device in security_devices:
            if not isinstance(device, dict):
                continue
            attributes = device.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            name = attributes.get("name", device.get("id", "unknown"))
            device_type = attributes.get("device_type", attributes.get("product_type", "unknown"))
            device_names.append(str(name))
            if str(device_type) not in device_types:
                device_types.append(str(device_type))

        is_configured = total_devices > 0

        return {
            "isMDRConfigured": is_configured,
            "totalSecurityDevices": total_devices,
            "deviceNames": device_names,
            "deviceTypes": device_types
        }
    except Exception as e:
        return {"isMDRConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMDRConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_devices = eval_result.get("totalSecurityDevices", 0)
        device_names = eval_result.get("deviceNames", [])
        device_types = eval_result.get("deviceTypes", [])

        if result_value:
            pass_reasons.append("MDR is configured: " + str(total_devices) + " security device(s) registered in Expel Workbench.")
            if device_types:
                additional_findings.append("Device types detected: " + ", ".join(device_types))
            for name in device_names:
                additional_findings.append("Registered device: " + str(name))
        else:
            fail_reasons.append("No security devices found in Expel Workbench. MDR cannot be considered configured without at least one monitored device.")
            recommendations.append("Connect at least one security device (e.g., SIEM, EDR, firewall) to Expel Workbench to configure MDR monitoring coverage.")

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSecurityDevices": total_devices}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
