"""
Transformation: confirmLicensePurchased
Vendor: Crowdstrike  |  Category: claims-defense
Evaluates: Verify that devices are enrolled and reporting into the CrowdStrike Falcon platform
(meta.pagination.total > 0), confirming an active product subscription and license is in place.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmLicensePurchased", "vendor": "Crowdstrike", "category": "claims-defense"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total = data.get("total", 0)
        if not isinstance(total, int):
            total = 0
        device_count = len(resources)
        effective_total = total if total > 0 else device_count
        is_licensed = effective_total > 0
        return {
            "confirmLicensePurchased": is_licensed,
            "totalDevicesReported": effective_total,
            "enrolledDeviceCount": device_count
        }
    except Exception as e:
        return {"confirmLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("CrowdStrike Falcon devices are enrolled and actively reporting, confirming an active license.")
            pass_reasons.append("Total devices reported: " + str(eval_result.get("totalDevicesReported", 0)))
        else:
            fail_reasons.append("No devices found reporting into the CrowdStrike Falcon platform.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Falcon sensor is deployed and devices are enrolled in the CrowdStrike Falcon platform.")
            recommendations.append("Verify that a valid CrowdStrike license is active and the API credentials have Hosts read scope.")
        additional_findings.append("Enrolled device count: " + str(eval_result.get("enrolledDeviceCount", 0)))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
