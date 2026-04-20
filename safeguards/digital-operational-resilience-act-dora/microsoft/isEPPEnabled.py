"""
Transformation: isEPPEnabled
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether EPP/antivirus agent is deployed and enforced on managed endpoints via Intune managed devices.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def evaluate(data):
    try:
        devices = data.get("value", [])
        total = len(devices)
        if total == 0:
            return {"isEPPEnabled": False, "totalDevices": 0, "compliantDevices": 0, "scoreInPercentage": 0.0}
        compliant_count = 0
        for device in devices:
            state = device.get("complianceState", "")
            if state.lower() == "compliant":
                compliant_count = compliant_count + 1
        score = (compliant_count / total) * 100
        is_enabled = compliant_count > 0
        return {
            "isEPPEnabled": is_enabled,
            "totalDevices": total,
            "compliantDevices": compliant_count,
            "scoreInPercentage": round(score, 2)
        }
    except Exception as e:
        return {"isEPPEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabled"
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
        if result_value:
            pass_reasons.append("Intune managed devices with compliant state found — EPP is deployed and enforced")
            pass_reasons.append("Compliant devices: " + str(extra_fields.get("compliantDevices", 0)) + " of " + str(extra_fields.get("totalDevices", 0)) + " (" + str(extra_fields.get("scoreInPercentage", 0)) + "%)")
        else:
            fail_reasons.append("No Intune managed devices found with compliant complianceState")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enroll devices in Microsoft Intune and configure device compliance policies that require an active EPP/antivirus agent")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
