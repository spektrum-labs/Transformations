"""
Transformation: isEPPEnabled
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether managed devices report a compliant endpoint protection status (complianceState = 'compliant').
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabled", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        devices = data.get("value", [])
        total = len(devices)
        if total == 0:
            return {"isEPPEnabled": False, "totalDevices": 0, "compliantCount": 0, "complianceRate": 0.0}
        compliant_count = 0
        for d in devices:
            if d.get("complianceState", "") == "compliant":
                compliant_count = compliant_count + 1
        compliance_rate = (compliant_count * 100.0) / total
        enabled = compliant_count > 0
        return {
            "isEPPEnabled": enabled,
            "totalDevices": total,
            "compliantCount": compliant_count,
            "nonCompliantCount": total - compliant_count,
            "complianceRate": compliance_rate
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
            pass_reasons.append("Compliant managed devices found with EPP active")
            pass_reasons.append("Compliant: " + str(extra_fields.get("compliantCount", 0)) + " of " + str(extra_fields.get("totalDevices", 0)) + " devices (" + str(round(extra_fields.get("complianceRate", 0.0), 2)) + "%)")
        else:
            fail_reasons.append("No compliant managed devices found; EPP cannot be confirmed as enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enroll devices in Microsoft Intune and ensure compliance policies requiring Microsoft Defender antivirus are applied and met")
        combined = {criteriaKey: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalDevices": extra_fields.get("totalDevices", 0), "compliantCount": extra_fields.get("compliantCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
