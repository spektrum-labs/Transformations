"""
Transformation: requiredCoveragePercentage
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Calculates the percentage of managed devices that are compliant (EPP coverage).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def get_devices(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        devices = get_devices(data)
        total = len(devices)
        if total == 0:
            return {"requiredCoveragePercentage": 0, "error": "No managed devices found", "totalDevices": 0, "compliantDevices": 0, "nonCompliantDevices": 0}

        compliant_count = 0
        non_compliant_count = 0
        in_grace_count = 0
        unknown_count = 0

        for device in devices:
            state = device.get("complianceState", "unknown")
            if state == "compliant":
                compliant_count = compliant_count + 1
            elif state == "noncompliant":
                non_compliant_count = non_compliant_count + 1
            elif state == "inGracePeriod":
                in_grace_count = in_grace_count + 1
            else:
                unknown_count = unknown_count + 1

        percentage = (compliant_count * 100) / total

        return {
            "requiredCoveragePercentage": round(percentage, 2),
            "totalDevices": total,
            "compliantDevices": compliant_count,
            "nonCompliantDevices": non_compliant_count,
            "inGracePeriodDevices": in_grace_count,
            "unknownStateDevices": unknown_count,
            "scoreInPercentage": round(percentage, 2)
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: 0}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, 0)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value >= 80:
            pass_reasons.append("Device compliance coverage is at " + str(result_value) + "%, meeting the required threshold")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Device compliance coverage is " + str(result_value) + "%, which may be below the required threshold")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Investigate non-compliant devices in Microsoft Intune and remediate to improve endpoint protection coverage")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: 0}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
