"""
Transformation: requiredCoveragePercentage
Vendor: Crowdstrike  |  Category: epp
Evaluates: The percentage of endpoints with active Falcon sensor coverage.
           Coverage is defined as devices with status='normal' or
           reduced_functionality_mode='no'. Returns a score as a percentage.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def get_devices(data):
    """Extract device records from merged or direct API response."""
    if isinstance(data, dict):
        method_data = data.get("getDevices", None)
        if method_data is not None:
            if isinstance(method_data, dict):
                return method_data.get("data", [])
            if isinstance(method_data, list):
                return method_data
        direct = data.get("data", None)
        if isinstance(direct, list):
            return direct
        resources = data.get("resources", None)
        if isinstance(resources, list):
            return resources
    if isinstance(data, list):
        return data
    return []


def device_is_covered(device):
    """
    Return True if a device has active Falcon sensor coverage.
    Coverage criteria:
      - status == 'normal'  (sensor fully operational)
      - OR reduced_functionality_mode == 'no'  (sensor not degraded)
    """
    status = device.get("status", "")
    rfm = device.get("reduced_functionality_mode", "")
    if status == "normal":
        return True
    if rfm == "no":
        return True
    return False


def evaluate(data):
    """Compute coverage percentage across all enrolled devices."""
    try:
        devices = get_devices(data)
        total_devices = len(devices)
        if total_devices == 0:
            return {
                "requiredCoveragePercentage": 0.0,
                "scoreInPercentage": 0.0,
                "totalDevices": 0,
                "coveredDevices": 0,
                "uncoveredDevices": 0
            }
        covered = [d for d in devices if device_is_covered(d)]
        covered_count = len(covered)
        uncovered_count = total_devices - covered_count
        coverage_pct = round((covered_count / total_devices) * 100, 2)
        return {
            "requiredCoveragePercentage": coverage_pct,
            "scoreInPercentage": coverage_pct,
            "totalDevices": total_devices,
            "coveredDevices": covered_count,
            "uncoveredDevices": uncovered_count
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
        total = eval_result.get("totalDevices", 0)
        covered = eval_result.get("coveredDevices", 0)
        uncovered = eval_result.get("uncoveredDevices", 0)
        if total == 0:
            fail_reasons.append("No device records returned by the API — unable to calculate coverage percentage.")
            recommendations.append("Verify API credentials have Hosts Read scope and that devices are enrolled in the Falcon tenant.")
        else:
            summary = str(covered) + " of " + str(total) + " devices have active Falcon sensor coverage (" + str(result_value) + "%)." 
            if result_value >= 95.0:
                pass_reasons.append(summary)
            else:
                fail_reasons.append(summary)
                recommendations.append("Investigate and remediate " + str(uncovered) + " device(s) without active Falcon sensor coverage. Check for sensor installation failures or devices in Reduced Functionality Mode (RFM).")
        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])
        if uncovered > 0:
            additional_findings.append(str(uncovered) + " device(s) are not covered — verify sensor health and RFM status in the Falcon Console.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalDevices": total, "coveredDevices": covered, "uncoveredDevices": uncovered, "scoreInPercentage": result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
